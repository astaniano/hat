 There are two different types of NoSQL injection:
 - Syntax injection - This occurs when you can break the NoSQL query syntax, enabling you to inject your own payload. The methodology is similar to that used in SQL injection. However the nature of the attack varies significantly, as NoSQL databases use a range of query languages, types of query syntax, and different data structures.
 - Operator injection - This occurs when you can use NoSQL query operators to manipulate queries.

### Lab: Detecting NoSQL injection




## Detecting syntax injection in MongoDB
Consider a shopping application that displays products in different categories. When the user selects the Fizzy drinks category, their browser requests the following URL:
```
https://insecure-website.com/product/lookup?category=fizzy
```
 This causes the application to send a JSON query to retrieve relevant products from the `product` collection in the MongoDB database:
```
this.category == 'fizzy'
```
To test whether the input may be vulnerable, submit a fuzz string in the value of the `category` parameter. An example string for MongoDB is: 
```
'"`{
;$Foo}
$Foo \xYZ
```
Use this fuzz string to construct the following attack:
```
https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```
If this causes a change from the original response, this may indicate that user input isn't filtered or sanitized correctly.

> Note
> 
> NoSQL injection vulnerabilities can occur in a variety of contexts, and you need to adapt your fuzz strings accordingly. Otherwise, you may simply trigger validation errors that mean the application never executes your query.  
> In this example, we're injecting the fuzz string via the URL, so the string is URL-encoded. In some applications, you may need to inject your payload via a JSON property instead. In this case, this payload would become:
```
 '\"`{\r;$Foo}\n$Foo \\xYZ\u0000 
```



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

### Tip from the lab:
Change the value of the username parameter from `{"$ne":""}` to `{"$regex":"wien.*"}`, then send the request. Notice that you can also log in when using the `$regex` operator.

