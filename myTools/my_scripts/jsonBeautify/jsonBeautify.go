package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	// JSON string to beautify
	jsonString := `{"results":[{"id":29,"ercPartNumber":"05L907309AH","dpvdPartNumber":"","ercCategory":"Fuel Metering System[06] - ECU[01] - ECU Hardware","description":"","countryOfProduction":"GERMANY","createdAt":"2024-09-09T15:53:45.600Z","pon":"1120242574504","modelCode":"DA147Z"},{"id":54,"ercPartNumber":"05L131705AB","dpvdPartNumber":"05L131705XX","ercCategory":"Exhaust Gas Conversion System[01] - Catalytic Converter[02] - Catalytic Converter","description":"SPANNELEMENT","countryOfProduction":"MACEDONIA (MKD)","createdAt":"2024-09-20T13:07:19.808Z","pon":"1120242574504","modelCode":"DA147Z"},{"id":55,"ercPartNumber":"05L131705AB","dpvdPartNumber":"","ercCategory":"Exhaust Gas Conversion System[01] - Catalytic Converter[02] - Catalytic Converter","description":"","countryOfProduction":"MACEDONIA (MKD)","createdAt":"2024-09-20T13:07:20.079Z","pon":"1120243974501","modelCode":"DA147Z"},{"id":29,"ercPartNumber":"05L907309AH","dpvdPartNumber":"","ercCategory":"Fuel Metering System[06] - ECU[01] - ECU Hardware","description":"","countryOfProduction":"GERMANY","createdAt":"2024-09-09T15:53:45.600Z","pon":"1120243974501","modelCode":"DA147Z"}],"message":"Job is in SUCCEEDED state.","status":"SUCCEEDED","metadata":{"ercFileName":"erc_support2.xlsx","dpvdFileName":"dpvd_support2.xlsx","pbkFileNames":["copy_pbk_support2.xlsx"],"createdAt":"2024-10-02T12:53:21.547Z","updatedAt":"2024-10-02T12:53:21.867Z"}}`

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

	// Print the beautified JSON
	fmt.Println(string(beautifiedJSON))
}
