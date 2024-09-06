### Username enumeration
- try to register a new user with the username that is already taken
- check response codes in user login
- error messages in user login:
  - response length: even by 1 character (when ther's a typo err)
- check response time: send as long password as possible and if the username is correct the response time may be longer than usual
- via account lock:
  - Sometimes an application may respond invalid username or password but in case we hit the username that exists more than let's say 3 times the response will be different. E.g.: You have made too many incorrect login attempts

### Brute-forcing usernames
- Can you access private user profiles without loggin in as those users?
- Profile name may sometimes be the same as the login username
- Check HTTP responses to see if any email addresses are disclosed in http responses

### Flawed brute-force protection
> Note: IP block can sometimes be evaded with `X-Forwarded-For` header

- The counter for the number of failed attempts resets if the IP owner logs in successfully to his own account
- Block account without blocking the IP:
  - pick for example 3 most popular passwords and use them to login to hundreds of accounts
- Multiple passwords per request:
  - `{ "password": "some passs" }` to an array:
`{ "password": ["some passs", "another pass"] }`

### Bypassing two-factor authentication
> Note may be useful to check TTL of mfa-codes
- websites don't check the second verification step of MFA and you can visit "logged-in only" pages after the correct username and password
- After a user has completed the initial login step, the website doesn't adequately verify that the same user is completing the second step. 
- 2FA bypass using a brute-force attack

### Brute-forcing a stay-logged-in cookie

### If not possible to crate your own account try to steal existing user cookies

### Reset password token is not checked twice

### Password reset poisoning (AKA stealing pass reset token if user clicks on url)
Try changing the `Host` or adding `X-Forwarded-Host` header which will change the url that victim will receive to their email. Then wait for the victim to click on that link

### Password brute-force via password change (see reset_pass.go)

### Identification and authentication failures

