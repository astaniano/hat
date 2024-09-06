package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

var (
	proxyURL, _ = url.Parse("http://localhost:8080")
	httpClient  = http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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

func rawHttpLikeOutput(resp *http.Response, closeBody bool) {
	if closeBody {
		defer resp.Body.Close()
	}

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

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
