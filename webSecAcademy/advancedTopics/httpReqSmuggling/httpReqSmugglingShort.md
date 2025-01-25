### Using HTTP request smuggling to turn an on-site redirect into an open redirect
For example:
There's a req:
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

### HTTP Request Smuggler extension docs:
```
https://github.com/PortSwigger/http-request-smuggler
```
For http 1.1 we use it by right clicking on a req > extensions > http req smuggler > smuggle probe

### HTTP desync attacks: Request smuggling reborn
```
https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
```

### HTTP/2: The sequel is always worse
```
https://portswigger.net/research/http2
```

### Browser-powered desync attacks: A new frontier in HTTP request smuggling
```
https://portswigger.net/research/browser-powered-desync-attacks
```
