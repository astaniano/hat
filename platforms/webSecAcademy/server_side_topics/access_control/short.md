### Check /admin url

### Check robots.txt (it may contain url for admins)

### Check the source code: 
Sometimes it may contain tricky admin urls, e.g.: `/administrator-panel-yb556`

### Change user role if it's possible
{"email":"haha@gmail.com"}
Change it to:
{"email":"haha@gmail.com", "roleid": 2}

### Circumvent access by adding `X-Original-URL` and `X-Rewrite-URL` headers

### Circumvent access by changing the HTTP method

### Circumvent access by searching for URL-matching discrepancies 

### Circumvent access by changing req params

### If you're not allowed to access and is redirected, check redirects

### Multi-step process with no access control on one step

### Referer-based access control

