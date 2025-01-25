hacktricks url:
```bash
https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection
```

### SSTI discovery steps:
1. look for reflection of our user controlled input
1. figure out if it is simply reflected or is it also evaluated
1. if our payload is evaluated - enumerate the templating engine
1. once you know templating engine - exploit the vulnerability

### When we think we identified the SSTI
We first try to send TI payloads (from hacktricks)
and if they don't work we try to induce an error that would reveal the templating engine

### identify TE with intruder:
We send to the intruder our request and use the payloads from hacktricks to detect the templating engine.
Request:
```bash
GET /?message=§Unfortunately%20this%20product%20is%20out%20of%20stock§ HTTP/2
```
In the intruder in Payloads we select `Payload type: Simple list` and in payloads we paste the payloads from [hacktricks](https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection)
```bash
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
```
Also a cool thing in burp intruder called `Grep extract` can simplify the response checking for us
In intruder we click `Settings` and go to `Grep extract` section and click on `Add` and we highlight `Unfortunately%20this%20product%20is%20out%20of%20stock` and press `ok`


