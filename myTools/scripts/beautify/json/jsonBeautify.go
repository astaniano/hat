package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	// JSON string to beautify
	jsonString := `

	`

	// Declare a variable to hold the unmarshalled data
	var jsonData interface{}

	// Unmarshal the JSON data
	if err := json.Unmarshal([]byte(jsonString), &jsonData); err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		return
	}

	// Marshal the data with indentation
	beautifiedJSON, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		return
	}

	filePath := "../beautified.txt"

	// Open the file for writing. If it doesn't exist, create it.
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Write the string to the file
	_, err = file.WriteString(string(beautifiedJSON))
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	fmt.Printf("Beautified JSON has been written to: %s\n", filePath)
}

