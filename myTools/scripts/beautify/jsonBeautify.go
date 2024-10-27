package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	// JSON string to beautify
	jsonString := `
	{}
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

	file, err := os.Create("./res.txt")
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
}
