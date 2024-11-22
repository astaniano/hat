package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func mainHtml(w http.ResponseWriter, r *http.Request) {
	// TODO: add current file location + ./serveHtml.html
	htmlFile, err := os.Open("./index.html")
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

func main() {
	// http.HandleFunc("/", mainHtml)
	http.HandleFunc("/test", test)
	http.HandleFunc("/redirect", redirect)

	// Serve static files (like index.js) from the current directory
	// TODO: add current file location + ./
	fs := http.FileServer(http.Dir("./assets"))

	// http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.Handle("/", fs)

	var port = ":3006"
	fmt.Println("Starting server on:")
	fmt.Println("http://localhost" + port)
	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}

func test(w http.ResponseWriter, r *http.Request) {
	fmt.Println("in test")
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

func redirect(w http.ResponseWriter, r *http.Request) {
	fmt.Println("in redirect")
	http.Redirect(w, r, "http://localhost:3000/index2.html?nintendo=55", http.StatusFound)
}
