package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"strings"
)

var (
	httpClient = http.Client{
		Transport: getHttpTransport(false),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func getHttpTransport(withProxie bool) *http.Transport {
	if withProxie {
		proxyURL, _ := url.Parse("http://localhost:8080")
		return &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &http.Transport{}
}

func makeHttpReq(method, url, body string, returnResp bool) *http.Response {
	data := strings.NewReader(body)

	req, _ := http.NewRequest(method, url, data)
	// req.Header.Add("Cookie", cookie)
	req.Header.Add("Authorization", "Basic amFuZV9iYXplbkBnbWFpbC5jb206VHl6eDU2PSplZjNmLS0tMw==")
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

	fw, err := writer.CreateFormField("__RequestVerificationToken")
	checkErr(err)
	_, err = io.Copy(fw, strings.NewReader("CfDJ8Ev7RV7_tOpHkjS-oAG4nqqVsI1CgU3MuV-mEbMsRKMTn_ykJi3WbA-cTnAyyl1cWAGIc6QtIPu-gPiT3IXmtLvp-_I9DIoqR3ehT6J8eULAqEDL818sXtq_zO24oQXBxL4lqx1JBSEXlN1J_Wq_ZWQ"))
	checkErr(err)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="UploadedFile"; filename="`+fileName+`"`)
	h.Set("Content-Type", `text/plain`)
	fw, err = writer.CreatePart(h)
	checkErr(err)
	phpFile, err := os.Open("/home/user1/Downloads/" + fileName)
	checkErr(err)
	_, err = io.Copy(fw, phpFile)
	checkErr(err)

	writer.Close()

	req, err := http.NewRequest(method, url, bytes.NewReader(body.Bytes()))
	checkErr(err)
	req.Header.Add("Authorization", "Basic amFuZV9iYXplbkBnbWFpbC5jb206VHl6eDU2PSplZjNmLS0tMw==")
	req.Header.Add("Content-Type", writer.FormDataContentType())
	resp, err := httpClient.Do(req)
	checkErr(err)

	// if resp.StatusCode != http.StatusOK {
	// 	log.Printf("Request failed with response code: %d", resp.StatusCode)
	// }

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
