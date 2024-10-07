package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func mainHtml(w http.ResponseWriter, r *http.Request) {
	htmlContent := `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Simple Go Server</title>
    </head>
    <body>
        <h1>Hello, World!</h1>
        <p>This is a simple HTML page served by a Go HTTP server.</p>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <label for="file">Choose a file:</label>
            <input type="file" id="file" name="file" />
            <button type="submit">Upload</button>
        </form>
    </body>
    </html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, htmlContent)
}

const uploadPath = "./uploads/"

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse the form data
		err := r.ParseMultipartForm(10 << 20) // 10 MB limit
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		// Get the file from the form input
		file, fileHeader, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Error retrieving file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Create a new file in the upload directory
		out, err := os.Create(uploadPath + fileHeader.Filename)
		if err != nil {
			http.Error(w, "Error saving file", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		// Copy the uploaded file to the new file
		_, err = io.Copy(out, file)
		if err != nil {
			http.Error(w, "Error saving file", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "File successfully uploaded")
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func main() {
	http.HandleFunc("/", mainHtml)
	http.HandleFunc("/upload", uploadHandler)

	var port = ":3000"
	fmt.Println("Starting server on " + port)
	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}