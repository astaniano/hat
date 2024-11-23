### Username enumeration
- try to register a new user with the username that is already taken
- check response codes in user login
- error messages in user login:
  - response length: even by 1 character (when there's a typo err)
- check response time: send as long password as possible and if the username is correct the response time may be longer than usual
- via account lock:
  - Sometimes an application may respond invalid username or password but in case we hit the username that exists more than let's say 3 times the response will be different. E.g.: You have made too many incorrect login attempts

### Brute-forcing usernames
- Can you access private user profiles without loggin in as those users?
- Profile name may sometimes be the same as the login username
- Check HTTP responses to see if any email addresses are disclosed in http responses

Usernames are especially easy to guess if they conform to a recognizable pattern, such as an email address. For example, it is very common to see business logins in the format firstname.lastname@somecompany.com. However, even if there is no obvious pattern, sometimes even high-privileged accounts are created using predictable usernames, such as admin or administrator.

During auditing, check whether the website discloses potential usernames publicly. For example, are you able to access user profiles without logging in? Even if the actual content of the profiles is hidden, the name used in the profile is sometimes the same as the login username. You should also check HTTP responses to see if any email addresses are disclosed. Occasionally, responses contain email addresses of high-privileged users, such as administrators or IT support. 

### Flawed brute-force protection
> Note: IP block can sometimes be evaded with `X-Forwarded-For` header

- The counter for the number of failed attempts resets if the IP owner logs in successfully to his own account
  - for example, you might sometimes find that your IP is blocked if you fail to log in too many times. In some implementations, the counter for the number of failed attempts resets if the IP owner logs in successfully. This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached.
- Block account without blocking the IP:
  - pick for example 3 most popular passwords and use them to login to hundreds of accounts
- Multiple passwords per request:
  - `{ "password": "some passs" }` to an array:
`{ "password": ["some passs", "another pass"] }`

## Two-factor authentication
> Note: may be useful to check TTL of mfa-codes

### Lab: 2FA simple bypass
Websites may not check the second verification step of MFA and you can visit "logged-in only" pages after the first step of MFA flow. (i.e. after correct username and password were submitted)
i.e. websites ignore the second step of MFA flow and after username and password - the user is already logged in

### Flawed two-factor verification logic
Sometimes flawed logic in two-factor authentication means that after a user has completed the initial login step, the website doesn't adequately verify that the same user is completing the second step:  
For example, the user logs in with their normal credentials in the first step as follows:  
```
POST /login-steps/first HTTP/1.1
Host: vulnerable-website.com
...
username=carlos&password=qwerty
```
They are then assigned a cookie that relates to their account, before being taken to the second step of the login process:
```
HTTP/1.1 200 OK
Set-Cookie: account=carlos

GET /login-steps/second HTTP/1.1
Cookie: account=carlos
```
When submitting the verification code, the request uses this cookie to determine which account the user is trying to access:
```
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=carlos
...
verification-code=123456
```
In this case, an attacker could log in using their own credentials but then change the value of the account cookie to any arbitrary username when submitting the verification code.
```
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=victim-user
...
verification-code=123456
```
This is extremely dangerous if the attacker is then able to brute-force the verification code as it would allow them to log in to arbitrary users' accounts based entirely on their username. They would never even need to know the user's password.   

### Lab: 2FA broken logic:
e.g. make a request to `POST /login` req.body: `user=wiener&password=peter` 
as a response we are redirected to `GET /login2` which generates on the backend a 4 digit mfa code and sends it via sms or email  
When we got the 4 digit code we submit it with `POST /login2` req.body: `mfa-code=1234`  
As a response we get a `SetCookie header: session=afasdfsf` and a redirect to a user home page  
If the mfa logic is broken then we can generate mfa-code for another user by making `GET /login2` request and changing the header `Cookie: verify=wiener` to `Cookie: verify=carlos` and it will generate a new mfa-code for carlos.   
Later we can brute-force that code and get back a `SetCookie` header with the session for carlos.

### Lab: 2FA bypass using a brute-force attack  
Some websites attempt to prevent mfa bruteforce by automatically logging a user out if they enter a certain number of incorrect verification codes.
It can be circumvented by writing a script that logs in our user and tries to brute force mfa code.
> Note: script may need to be run 2 or more times as it is also possible that sometimes new login may generate mfa code that has already been tried before...

### Brute-forcing a stay-logged-in cookie
Some websites generate this cookie based on a predictable concatenation of static values, such as the username and a timestamp
- login to your account and look at the stay-logged-in cookie 
- try to figure out how it is generated and whether it can be brute forced
- if successful go to another url with that cookie e.g. /account

### Reset password token is not checked twice 
See `./pass_reset_flow.md` file for details of the pass reset flow

In the second request change the value of `temp-forgot-password-token` to any random string and observe if it resets the password. If it does - then this reset token is not checked (for being related to a user) properly for the second time

### Password reset poisoning (AKA stealing pass reset token if user clicks on url)
See `./pass_reset_flow.md` file for details of the pass reset flow

If the URL that is sent to the user's email is dynamically generated based on controllable input, such as the `Host` header we can do the following:

Submit a password reset request on the behalf of user that we're trying to attack. When submitting the form intercept the resulting HTTP request and modify the `Host` header so that it points to a domain (server) that you control

Later the victim will receive the pass reset link to their email and if victim clicks on it (or it is fetched in some other way, for example, by an antivirus scanner) - you'll see their real reset token in the server logs

If `Host` header does not change the generated url you can try to add additional header `X-Forwarded-Host` which may change the resulting url

> Note: Try changing the `Host` or adding `X-Forwarded-Host` header which will change the url that victim will receive to their email. Then wait for the victim to click on that link

> Note: neither `Host` nor `X-Forwarded-Host` should contain "https://"

> Note: Even if you can't control the password reset link, you can sometimes use the `Host` header to inject HTML into sensitive emails. Note that email clients typically don't execute JavaScript, but other HTML injection techniques like dangling markup attacks may still apply. 

> Note: In a real attack, the attacker may seek to increase the probability of the victim clicking the link by first warming them up with a fake breach notification

### Password brute-force via password change (see reset_pass.go)
Password change functionality can be particularly dangerous if it allows an attacker to access it directly without being logged in as the victim user

if you enter two different new passwords, an error message simply states Current password is incorrect. If you enter a valid current password, but two different new passwords, the message says New passwords do not match. We can use this message to enumerate correct passwords. 

### Identification and authentication failures
> Taken from THM > OWASP TOP 10 2021 > Identification and authentication failures

Say there is an existing user with the name `admin`, and we want access to their account, so what we can do is try to re-register that username but with slight modification.

We will enter " admin" without the quotes (notice the space at the start). Now when you enter that in the username field and enter other required information like `email` `id` or `password` and submit that data, it will register a new user, but that user will have the same right as the admin account. That new user will also be able to see all the content presented under the user admin.
