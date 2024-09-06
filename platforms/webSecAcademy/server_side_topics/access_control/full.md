### Check the source code: 
Imagine an application that hosts administrative functions at the following URL: 
```
https://insecure-website.com/administrator-panel-yb556
```
This might not be directly guessable by an attacker. However, the application might still leak the URL to users. The URL might be disclosed in JavaScript that constructs the user interface based on the user's role: 
```
<script>
	var isAdmin = false;
	if (isAdmin) {
		...
		var adminPanelTag = document.createElement('a');
		adminPanelTag.setAttribute('https://insecure-website.com/administrator-panel-yb556');
		adminPanelTag.innerText = 'Admin panel';
		...
	}
</script>
```
This script adds a link to the user's UI if they are an admin user. However, the script containing the URL is visible to all users regardless of their role.

### Try to change user role if it's possible
Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:
- A hidden field.
- A cookie.
- A preset query string parameter.
For example: 
```
https://insecure-website.com/login/home.jsp?admin=true
https://insecure-website.com/login/home.jsp?role=1
```
#### Lab example:
Sometimes you can observe that the response from email update contains your role ID.
Let's say there is a change email functionality with the following req.body:
```
{"email":"haha@gmail.com"}
```
Change it to:
```
{"email":"haha@gmail.com", "roleid": 2}
```
This can modify the user roleid (e.g. it was 1 and after the change email it becomes 2)

### Circumvent access by adding `X-Original-URL` and `X-Rewrite-URL` headers
Some applications enforce access controls at the platform layer. they do this by restricting access to specific URLs and HTTP methods based on the user's role. For example, an application might configure a rule as follows:
```
DENY: POST, /admin/deleteUser, managers
```
This rule denies access to the `POST` method on the URL `/admin/deleteUser`, for users in the managers group. Various things can go wrong in this situation, leading to access control bypasses.

Some application frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as `X-Original-URL` and `X-Rewrite-URL`. If a website uses rigorous front-end controls to restrict access based on the URL, but the application allows the URL to be overridden via a request header, then it might be possible to bypass the access controls using a request like the following: 
```
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
...
```

#### Lab: URL-based access control can be circumvented
Send the request to Burp Repeater. Change the URL in the request line to / and add the HTTP header X-Original-URL: /invalid. Observe that the application returns a "not found" response. This indicates that the back-end system is processing the URL from the X-Original-URL header. 

Change the value of the X-Original-URL header to /admin. Observe that you can now access the admin page. 

### Circumvent access by changing the HTTP method
Let's say there's a `POST` method that requires admin priviledges.
If you try to submit that request as a regular user you'll get an err: Unauthorized. But changing the request to `GET` does not give an err and does the action that you're trying to do.

> Note: you can e.g. try to change `POST` to POSTX in the beginning and see if it accepts a different http method

### Circumvent access by searching for URL-matching discrepancies 
Websites can vary in how strictly they match the path of an incoming request to a defined endpoint. For example, they may tolerate inconsistent capitalization, so a request to `/ADMIN/DELETEUSER` may still be mapped to the `/admin/deleteUser` endpoint. If the access control mechanism is less tolerant, it may treat these as two different endpoints and fail to enforce the correct restrictions as a result.

Similar discrepancies can arise if developers using the Spring framework have enabled the `useSuffixPatternMatch` option. This allows paths with an arbitrary file extension to be mapped to an equivalent endpoint with no file extension. In other words, a request to `/admin/deleteUser.anything` would still match the `/admin/deleteUser` pattern. Prior to Spring 5.3, this option is enabled by default.

On other systems, you may encounter discrepancies in whether `/admin/deleteUser` and `/admin/deleteUser/` are treated as distinct endpoints. In this case, you may be able to bypass access controls by appending a trailing slash to the path. 

### Circumvent access by changing req params 
e.g. in the url change id to the id of another user:
```
https://insecure-website.com/myaccount?id=123
```
Also an application might use globally unique identifiers (GUIDs) to identify users. The GUIDs belonging to other users might be disclosed elsewhere in the application where users are referenced, such as user messages or reviews

Also try to get access to static files

### If you're not allowed to access and is redirected, check redirects
In some cases, an application does detect when the user is not permitted to access the resource, and returns a redirect to the login page. However, the response containing the redirect might still include some sensitive data belonging to the targeted user, so the attack is still successful.

### Multi-step process with no access control on one step
Imagine a website where access controls are correctly applied to the first and second steps, but not to the third step. The website assumes that a user will only reach step 3 if they have already completed the first steps, which are properly controlled. An attacker can gain unauthorized access to the function by skipping the first two steps and directly submitting the request for the third step with the required parameters. 

### Referer-based access control
Some websites base access controls on the Referer header submitted in the HTTP request.

For example, an application robustly enforces access control over the main administrative page at /admin, but for sub-pages such as /admin/deleteUser only inspects the Referer header. If the Referer header contains the main /admin URL, then the request is allowed. 
