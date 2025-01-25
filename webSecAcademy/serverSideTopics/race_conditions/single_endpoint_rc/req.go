package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"strings"
)

func makeHttpReq(method, url, body string) {
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

	// rawHttpLikeOutput(resp)
}

func rawHttpLikeOutput(resp *http.Response) {
	fmt.Println(resp.Proto + " " + resp.Status)
	for _, key := range reflect.ValueOf(resp.Header).MapKeys() {
		value := resp.Header[key.String()]
		fmt.Println(key, ":", value)
	}
	fmt.Println()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp_body := string(bodyBytes)
	fmt.Println(resp_body)
	fmt.Println("===========")
}
