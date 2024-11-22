package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

func beautifyXML(xmlString string) (string, error) {
	var result interface{}

	// Unmarshal the XML into a generic interface{} type
	err := xml.Unmarshal([]byte(xmlString), &result)
	if err != nil {
		return "", err
	}

	// Marshal the interface{} back into XML with indentation
	prettyXML, err := xml.MarshalIndent(result, "", "  ") // You can change the indentation level here
	if err != nil {
		return "", err
	}

	xmlString2 := `<root><child1>Value1</child1><child2>Value2</child2></root>`
    
    // Unmarshal the XML string into a generic interface
    var result2 interface{}
    err = xml.Unmarshal([]byte(xmlString2), &result2)
    if err != nil {
        fmt.Println("Error unmarshalling XML:", err)
    }

    // Marshal it back to a pretty-printed XML string
    output, err := xml.MarshalIndent(result2, "", "  ")
    if err != nil {
        fmt.Println("Error marshalling XML:", err)
    }

    // Print the pretty-printed XML
    fmt.Println(string(output))

	// Return the formatted XML as a string
	return string(prettyXML), nil
}

func writeToFile(filePath, content string) error {
	// Open the file for writing. If it doesn't exist, create it.
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the content to the file
	_, err = file.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	xmlString := `

	`

	// Beautify the XML string
	beautifiedXML, err := beautifyXML(xmlString)
	if err != nil {
		log.Fatalf("Error beautifying XML: %v", err)
	}

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatalf("Unable to get the current filename")
	}
	dirname := filepath.Dir(filename)
	filePath := filepath.Join(dirname, "..", "beautified.txt")

	err = writeToFile(filePath, beautifiedXML)
	if err != nil {
		log.Fatalf("Error writing to file: %v", err)
	}

	// fmt.Printf("Beautified XML has been written to: %s\n", filePath)
}
