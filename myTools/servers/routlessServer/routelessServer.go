package main

import (
	"fmt"
	"io"
	"net/http"
	"reflect"
)

type myHandler struct{}

func (s myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.RequestURI)
	for _, key := range reflect.ValueOf(r.Header).MapKeys() {
		value := r.Header[key.String()]
		fmt.Println(key, ":", value)
	}
	io.WriteString(w, "This is my website!\n")
}

func main() {
	var port = ":3001"
	fmt.Println("Starting server on " + port)

	if err := http.ListenAndServe(port, myHandler{}); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
