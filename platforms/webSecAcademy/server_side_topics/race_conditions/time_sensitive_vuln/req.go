package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"strings"
)

func makeHttpReq(method, url, body, cookie string, returnResp bool) *http.Response {
	data := strings.NewReader(body)

	req, _ := http.NewRequest(method, url, data)
	req.Header.Add("Cookie", cookie)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)

	if err != nil {
		log.Fatal(err)
		return nil
	}

	if returnResp {
		return resp
	}

	defer resp.Body.Close()

	return nil
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
