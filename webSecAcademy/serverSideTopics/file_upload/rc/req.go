package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"reflect"
	"strings"
)

var (
	// proxyURL, _ = url.Parse("http://localhost:8080")
	httpClient = http.Client{
		Transport: &http.Transport{
			// Proxy:           http.ProxyURL(proxyURL),
			// TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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

func uploadFileReq(method, url string) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	fw, err := writer.CreateFormField("user")
	checkErr(err)
	_, err = io.Copy(fw, strings.NewReader("wiener"))
	checkErr(err)

	fw, err = writer.CreateFormField("csrf")
	checkErr(err)
	_, err = io.Copy(fw, strings.NewReader("HP2VNr0DYboTDKeo6i9AzQLtqzGBznaW"))
	checkErr(err)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="avatar"; filename="`+fileName+`"`)
	h.Set("Content-Type", `image/png`)
	fw, err = writer.CreatePart(h)
	checkErr(err)
	pngFile, err := os.Open("/home/user1/Downloads/"+fileName)
	checkErr(err)
	_, err = io.Copy(fw, pngFile)
	checkErr(err)

	writer.Close()

	req, err := http.NewRequest(method, url, bytes.NewReader(body.Bytes()))
	checkErr(err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.Header.Add("Cookie", cookieSession)
	resp, _ := httpClient.Do(req)

	if resp.StatusCode != http.StatusOK {
		log.Printf("Request failed with response code: %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	// rawHttpLikeOutput(resp, false)
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
