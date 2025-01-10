### Supply an arbitrary Host header
When probing for Host header injection vulnerabilities, the first step is to test what happens when you supply an arbitrary, unrecognized domain name via the Host header.

Sometimes, you will still be able to access the target website even when you supply an unexpected Host header. This could be for a number of reasons. For example, servers are sometimes configured with a default or fallback option in case they receive requests for domain names that they don't recognize. If your target website happens to be the default, you're in luck. In this case, you can begin studying what the application does with the Host header and whether this behavior is exploitable.

### Check for flawed validation

## Send ambiguous requests
### Inject duplicate Host headers
Consider the following request:
```bash
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```

Let's say the front-end gives precedence to the first instance of the header, but the back-end prefers the final instance. Given this scenario, you could use the first header to ensure that your request is routed to the intended target and use the second header to pass your payload into the server-side code. 

### Supply an absolute URL

### Add line wrapping
Due to the highly inconsistent handling of this case, there will often be discrepancies between different systems that process your request. For example, consider the following request:
```bash
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```

### Inject host override headers
You can sometimes use X-Forwarded-Host to inject your malicious input while circumventing any validation on the Host header itself.
```bash
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```
Although `X-Forwarded-Host` is the de facto standard for this behavior, you may come across other headers that serve a similar purpose, including:
```bash
X-Host
X-Forwarded-Server
X-HTTP-Host-Override
Forwarded
```

Tip: In Burp Suite, you can use the `Param Miner` extension's "Guess headers" function to automatically probe for supported headers using its extensive built-in wordlist

### Web cache poisoning via the Host header

### Exploiting classic server-side vulnerabilities



