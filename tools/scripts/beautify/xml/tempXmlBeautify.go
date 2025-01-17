package main

import (
	"encoding/xml"
	"errors"
	"io"
	"log"
	"os"
)

func main() {
	openedFile, err := os.Open("./input.xml")
	if err != nil {
		return
	}
	defer openedFile.Close()

	xmlDecoder := xml.NewDecoder(openedFile)

	file, errr := os.OpenFile("../beautified.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if errr != nil {
		return
	}
	defer file.Close()

	xmlEncoder := xml.NewEncoder(file)
	xmlEncoder.Indent("", "  ")

	for {
		tokenXml, err := xmlDecoder.RawToken()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			log.Println(err)
			break
		}

		// switch tokenXml.(type) {
		//     case xml.ProcInst:
		//     	continue
		// }

		xmlEncoder.EncodeToken(tokenXml)
	}

	if err := xmlEncoder.Flush(); err != nil {
		log.Fatal(err)
	}
}
