package main

import (
	"io"
	"log"
	"net/http"
	"strings"
)

func makeHttpReq(method, url, body string) (respBody string) {
	data := strings.NewReader(body)

	req, _ := http.NewRequest(method, url, data)
	req.Header.Add("Cookie", "session="+session_cookie)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http_client.Do(req)

	if err != nil {
		log.Fatal(err)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	return string(bodyBytes)
}

