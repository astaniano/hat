package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func mainHtml(w http.ResponseWriter, r *http.Request) {
	htmlFile, err := os.Open("serveHtml.html")
	if err != nil {
		http.Error(w, "Could not open HTML file", http.StatusInternalServerError)
		return
	}
	defer htmlFile.Close()

	w.Header().Set("Content-Type", "text/html")

	// Copy the file content to the response writer
	if _, err := io.Copy(w, htmlFile); err != nil {
		http.Error(w, "Could not read HTML file", http.StatusInternalServerError)
	}
}

func test(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Could not read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close() // Ensure the body is closed after reading

	fmt.Println(r.RequestURI)
	fmt.Println("Request Body:", string(body))

	io.WriteString(w, "Success!\n")
}

func main() {
	http.HandleFunc("/", mainHtml)
	http.HandleFunc("/test", test)

	var port = ":3000"
	fmt.Println("Starting server on " + port)
	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
