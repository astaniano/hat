import os
import http.server
import socketserver

# curl example
# curl -X POST -H "filename: my_file.txt" --data-binary @path/to/local/file.txt http://<server_ip>:8080/

# Specify the directory where uploaded files will be stored
UPLOAD_DIR = "/home/user1/hat/thm/wonderland"

class FileUploadHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        try:
            # Create the uploads directory if it doesn't exist
            os.makedirs(UPLOAD_DIR, exist_ok=True)

            # Get the uploaded file data
            content_length = int(self.headers["Content-Length"])
            uploaded_file = self.rfile.read(content_length)

            # Extract the filename from the request
            filename = self.headers["filename"]

            # Save the file to the uploads directory
            with open(os.path.join(UPLOAD_DIR, filename), "wb") as f:
                f.write(uploaded_file)

            # Send a success response
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"File uploaded successfully!")
        except Exception as e:
            # Send an error response
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Error uploading file: {str(e)}".encode())

if __name__ == "__main__":
    PORT = 8080
    with socketserver.TCPServer(("", PORT), FileUploadHandler) as httpd:
        print(f"Server listening on port {PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            # Handle CTRL + C (SIGINT) gracefully
            print("Server interrupted. Shutting down gracefully...")
            httpd.server_close()


