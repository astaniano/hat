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

### Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
### Lab: SQL injection vulnerability allowing login bypass

### SQL injection UNION attacks
### Lab: SQL injection UNION attack, determining the number of columns returned by the query

### Database-specific syntax
On Oracle, every SELECT query must use the FROM keyword and specify a valid table. There is a built-in table on Oracle called dual which can be used for this purpose. So the injected queries on Oracle would need to look like: 
```bash
' UNION SELECT NULL FROM DUAL--
```
**On MySQL, the double-dash sequence must be followed by a space**

### Lab: SQL injection UNION attack, finding a column containing text
### Lab: SQL injection UNION attack, retrieving data from other tables
### Lab: SQL injection UNION attack, retrieving multiple values in a single column

### Blind SQL injection vulnerabilities
