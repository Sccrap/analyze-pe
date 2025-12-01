package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	peparser "github.com/saferwall/pe"
)

func usage() {
	fmt.Println("Usage: analyze-pe <file.exe|file.dll>")
	fmt.Println("Provide a PE executable or DLL to analyze.")
}

func isSupportedBinary(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".exe" || ext == ".dll"
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	filename := os.Args[1]
	if !isSupportedBinary(filename) {
		fmt.Printf("Unsupported file type for %q\n", filename)
		usage()
		return
	}

	pe, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		log.Fatalf("Error while opening file: %s, reason: %v", filename, err)
	}

	err = pe.Parse()
	if err != nil {
		log.Fatalf("Error while parsing file: %s, reason: %v", filename, err)
	}

	fmt.Printf("Successfully analyzed %s\n", filename)
}
