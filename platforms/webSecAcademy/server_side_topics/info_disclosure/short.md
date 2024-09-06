### Check /robots.txt or /sitemap.xml to see if you find anything of use 

### Send invalid input and check the error msg, it may contain some info disclosure:
- Try to get an err from the server, it may contain info about the framework and its version

### Search for debug info
/cgi-bin/phpinfo.php may contain logs and other useful info

### Try TRACE http method instead of GET, it may reveal some info e.g. auth headers:
- e.g. `/admin` may require custom http header to be equal to `localhost`:
`X-Custom-IP-Authorization: 127.0.0.1`

### check /.git url
- download the whole directory: wget -r https://YOUR-LAB-ID.web-security-academy.net/.git/
- use git dumper: ./gitdumper.sh <url/.git/> /home/user1/hat/web_sec_academy/info_disclosure/temp_git

