### CL.0 request smuggling
Request smuggling vulnerabilities are the result of discrepancies in how chained systems determine where each request starts and ends. This is typically due to inconsistent header parsing, leading to one server using a request's Content-Length and the other treating the message as chunked. However, it's possible to perform many of the same attacks without relying on either of these issues.

In some instances, servers can be persuaded to ignore the Content-Length header, meaning they assume that each request finishes at the end of the headers. This is effectively the same as treating the Content-Length as 0.

If the back-end server exhibits this behavior, but the front-end still uses the Content-Length header to determine where the request ends, you can potentially exploit this discrepancy for HTTP request smuggling. We've decided to call this a "CL.0" vulnerability. 

### Testing for CL.0 vulnerabilities


### PRACTITIONER Lab: CL.0 request smuggling

