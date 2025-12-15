package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/glaslos/ssdeep"
	peparser "github.com/saferwall/pe"
)

func help() {
	fmt.Println("Usage: analyzer <option> <file.exe|file.dll>")
	fmt.Println("Options:")
	fmt.Println("  -h, --help       Show this help message and exit")
	fmt.Println("  -i, --imports    Show imports")
	fmt.Println("  -s, --sections   Show sections")
	fmt.Println("  -b, --basic      Show basic information (SHA256, SSDEEP, size, machine)")
	fmt.Println("  -x, --strings    Export printable ASCII/UTF-16LE strings (optional output file)")
}

func sectionName(sec peparser.Section) string {
	nameBytes := sec.Header.Name[:]
	n := bytes.IndexByte(nameBytes, 0)
	if n == -1 {
		n = len(nameBytes)
	}
	return string(nameBytes[:n])
}

func basicInfo(filename string) error {

	// SHA256
	sha256sum, err := fileSHA256(filename)
	if err != nil {
		return fmt.Errorf("error calculating sha256: %v", err)
	}

	// SSDEEP
	ssdeepSum, err := fileSSDEEP(filename)
	if err != nil {
		return fmt.Errorf("error calculating ssdeep: %v", err)
	}

	// SIZE
	st, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("stat error: %v", err)
	}

	// MACHINE (PE header)
	f, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		return fmt.Errorf("error opening PE: %v", err)
	}
	if err := f.Parse(); err != nil {
		return fmt.Errorf("error parsing PE: %v", err)
	}

	machine := f.NtHeader.FileHeader.Machine.String()

	// OUTPUT BASIC INFO
	fmt.Printf("Basic info for %s:\n", filename)
	fmt.Println("--------------------------------------")
	fmt.Printf("File size:   %d bytes\n", st.Size())
	fmt.Printf("Machine:     %s\n", machine)
	fmt.Printf("SHA256:      %s\n", sha256sum)
	fmt.Printf("SSDEEP:      %s\n", ssdeepSum)
	fmt.Printf("Sections:    %d\n", len(f.Sections))
	fmt.Println("--------------------------------------")

	return nil
}

// Calculate SHA256
func fileSHA256(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	sum := h.Sum(nil)
	return fmt.Sprintf("%x", sum), nil
}

// Calculate SSDEEP
func fileSSDEEP(filename string) (string, error) {
	return ssdeep.FuzzyFilename(filename)
}

func extractStrings(filename string, minLen int, outFilename string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var results []string

	// ASCII strings
	var cur []byte
	for _, c := range b {
		if c >= 32 && c <= 126 {
			cur = append(cur, c)
		} else {
				results = append(results, string(cur))
			}
			cur = cur[:0]
		}
	}
	if len(cur) >= minLen {
		results = append(results, string(cur))
	}

	cur = cur[:0]
	for i := 0; i+1 < len(b); i += 2 {
		lo := b[i]
		hi := b[i+1]
		if hi == 0 && lo >= 32 && lo <= 126 {
			cur = append(cur, lo)
		} else {
			if len(cur) >= minLen {
				results = append(results, string(cur))
			}
			cur = cur[:0]
		}
	}
	if len(cur) >= minLen {
		results = append(results, string(cur))
	}

	// Output
	if outFilename == "" {
		for _, s := range results {
			fmt.Println(s)
		}
		return nil
	}

	f, err := os.Create(outFilename)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	for _, s := range results {
		if _, err := f.WriteString(s + "\n"); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}

	return nil
}

func sectionsPE(filename string) error {
	f, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}

	if err := f.Parse(); err != nil {
		return fmt.Errorf("error parsing PE: %w", err)
	}

	fmt.Printf("Successfully parsed %s\n", filename)
	fmt.Printf("Number of sections: %d\n", len(f.Sections))

	for _, sec := range f.Sections {
		name := sectionName(sec)
		vsize := sec.Header.VirtualSize
		char := sec.Header.Characteristics
		entropy := sec.CalculateEntropy(f)

		fmt.Printf("Section Name: %s\n", name)
		fmt.Printf("  VirtualSize: 0x%x\n", vsize)
		fmt.Printf("  Characteristics: 0x%x\n", char)
		fmt.Printf("  Entropy: %.3f\n\n", entropy)
	}

	return nil
}

func importsPE(filename string) error {
	f, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	if err := f.Parse(); err != nil {
		return fmt.Errorf("error parsing PE: %w", err)
	}

	if len(f.Imports) == 0 {
		log.Printf("No imports found in %s\n", filename)
		return nil
	}

	for _, imp := range f.Imports {
		log.Printf("DLL: %s", imp.Name)
		for _, e := range imp.Functions {
			if e.Name != "" {
				log.Printf("  -> %s", e.Name)
			} else {
				log.Printf("  -> ord: %d", e.Ordinal)
			}
		}
	}

	return nil
}

func main() {

	// Если только один аргумент — file.exe → выводим basic info
	if len(os.Args) == 2 {
		filename := os.Args[1]

		if strings.HasSuffix(strings.ToLower(filename), ".exe") ||
			strings.HasSuffix(strings.ToLower(filename), ".dll") {

			if err := basicInfo(filename); err != nil {
				fmt.Println("Error:", err)
			}
			return
		}

		fmt.Println("Invalid usage. Expected option or .exe/.dll file.")
		help()
		return
	}

	// Проверка количества аргументов
	if len(os.Args) < 3 {
		help()
		os.Exit(1)
	}

	flag := os.Args[1]
	filename := os.Args[2]

	// Проверка расширения файла
	lower := strings.ToLower(filename)
	if !strings.HasSuffix(lower, ".exe") && !strings.HasSuffix(lower, ".dll") {
		fmt.Println("Unsupported file type. Expected .exe or .dll")
		return
	}

	switch flag {

	case "-h", "--help":
		help()
		return

	case "-s", "--sections":
		if err := sectionsPE(filename); err != nil {
			fmt.Printf("Sections extraction error: %v\n", err)
			os.Exit(1)
		}

	case "-i", "--imports":
		if err := importsPE(filename); err != nil {
			fmt.Printf("Imports extraction error: %v\n", err)
			os.Exit(1)
		}

	case "-b", "--basic":
		if err := basicInfo(filename); err != nil {
			fmt.Printf("Basic info error: %v\n", err)
			os.Exit(1)
		}

	case "-x", "--strings":

		out := ""
		if len(os.Args) >= 4 {
			out = os.Args[3]
		}
		if err := extractStrings(filename, 4, out); err != nil {
			fmt.Printf("Strings extraction error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown option: %s\n", flag)
		help()
	}
}
