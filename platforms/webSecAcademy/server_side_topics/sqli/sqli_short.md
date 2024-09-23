First you determine the db you're dealing with
```
https://portswigger.net/web-security/sql-injection/cheat-sheet
```

The hardest is when there's an sql injection but errors are handeled gracefully and not returned and no data is returned 
And so the only way to exploit it is to try to trigger time delays

Sometimes server response time may not depend on db response time and there still might be sqli somewhere. In those cases we can use OAST attacks in order to trigger db to make a request and send some data in that request to our own remote server

## Check if table exists
' AND (SELECT 'x' FROM users LIMIT 1)='x'--
