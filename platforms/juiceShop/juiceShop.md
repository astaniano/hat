user login and password can be brute forced

when hitting an endpoint that doesn't exist, framework version is exposed:
http://localhost:3000/api.json

Reset password to 22 and then do login:
in /login endpoint 22  as password breaks the whole server : ))
{"email":"ff@ff.com","password":"22"}



