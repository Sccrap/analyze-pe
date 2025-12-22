package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/glaslos/ssdeep"
	peparser "github.com/saferwall/pe"
)

func help() {
	fmt.Println("Usage: analyzer <option> [file.exe|file.dll]")
	fmt.Println("Options:")
	fmt.Println("  -h, --help       Show this help message and exit")
	fmt.Println("  -w, --web        Launch web interface (http://localhost:8080)")
	fmt.Println("  -i, --imports    Show imports")
	fmt.Println("  -s, --sections   Show sections")
	fmt.Println("  -b, --basic      Show basic information (SHA256, SSDEEP, size, machine)")
	fmt.Println("  -x, --strings    Export printable ASCII/UTF-16LE strings (optional output file)")
	fmt.Println("  -d, --debug      Show debug directory information")
	fmt.Println("  --hex            View hex dump (usage: --hex file offset [size])")
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

	sha256sum, err := fileSHA256(filename)
	if err != nil {
		return fmt.Errorf("error calculating sha256: %v", err)
	}

	ssdeepSum, err := fileSSDEEP(filename)
	if err != nil {
		return fmt.Errorf("error calculating ssdeep: %v", err)
	}

	st, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("stat error: %v", err)
	}

	f, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		return fmt.Errorf("error opening PE: %v", err)
	}
	if err := f.Parse(); err != nil {
		return fmt.Errorf("error parsing PE: %v", err)
	}

	machine := f.NtHeader.FileHeader.Machine.String()

	language := detectLanguage(f)

	// OUTPUT BASIC INFO
	fmt.Printf("Basic info for %s:\n", filename)
	fmt.Println("--------------------------------------")
	fmt.Printf("File size:   %d bytes\n", st.Size())
	fmt.Printf("Machine:     %s\n", machine)
	fmt.Printf("Language:    %s\n", language)
	fmt.Printf("SHA256:      %s\n", sha256sum)
	fmt.Printf("SSDEEP:      %s\n", ssdeepSum)
	fmt.Printf("Sections:    %d\n", len(f.Sections))
	fmt.Println("--------------------------------------")

	return nil
}

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

func fileSSDEEP(filename string) (string, error) {
	return ssdeep.FuzzyFilename(filename)
}

func detectLanguage(f *peparser.File) string {
	importMap := make(map[string]bool)
	for _, imp := range f.Imports {
		importMap[strings.ToLower(imp.Name)] = true
	}

	sectionNames := make(map[string]bool)
	for _, sec := range f.Sections {
		name := sectionName(sec)
		sectionNames[strings.ToLower(name)] = true
	}

	// .NET detection (highest priority)
	if importMap["mscoree.dll"] {
		if importMap["mscorlib.dll"] {
			return ".NET (C#/VB.NET/F#) - CLR"
		}
		return ".NET (C#/VB.NET)"
	}
	
	// Visual C++ detection
	if sectionNames[".reloc"] && importMap["kernel32.dll"] && importMap["ntdll.dll"] {
		if importMap["msvcp140.dll"] || importMap["vcruntime140.dll"] || importMap["msvcp120.dll"] || importMap["msvcp110.dll"] {
			return "C/C++ (MSVC)"
		}
	}

	// Python detection
	pythonLibs := []string{
		"python3.dll", "python3.12.dll", "python3.11.dll", "python3.10.dll",
		"python3.9.dll", "python3.8.dll", "python3.7.dll", "python3.6.dll",
		"python.dll", "pythondll.dll",
	}
	for _, pylib := range pythonLibs {
		if importMap[pylib] {
			if sectionNames[".data"] {
				return "Python (Compiled)"
			}
			return "Python"
		}
	}

	// GCC/MinGW detection
	if importMap["libstdc++.dll"] || importMap["libgcc_s.dll"] || importMap["libwinpthread.dll"] {
		return "C/C++ (GCC/MinGW)"
	}

	// Delphi/Pascal detection
	if importMap["rtl.bpl"] || importMap["vcl.bpl"] || importMap["rtlx0.dll"] {
		return "Delphi/Pascal"
	}

	// Rust detection
	if len(f.Imports) == 1 && importMap["kernel32.dll"] {
		if sectionNames[".pdata"] {
			return "Rust (64-bit optimized)"
		}
		return "Rust"
	}

	// Go detection
	if importMap["kernel32.dll"] && importMap["ntdll.dll"] && len(f.Imports) <= 3 {
		if sectionNames[".go.buildinfo"] || sectionNames[".go.func"] {
			return "Go"
		}
		// Additional Go heuristic: minimal imports, .text section
		if len(f.Imports) <= 2 && len(f.Sections) >= 5 {
			return "Go (likely)"
		}
	}

	// Java/Kotlin detection (if compiled to Windows executable)
	if importMap["jvm.dll"] || importMap["java.dll"] || importMap["msvcr120.dll"] && len(f.Imports) >= 10 {
		return "Java/Kotlin"
	}

	// VB6 detection
	if importMap["msvbvm60.dll"] {
		return "Visual Basic 6"
	}

	// Clojure/JVM detection
	if sectionNames[".clj"] {
		return "Clojure"
	}

	// AutoIt detection
	if sectionNames[".rsrc"] && len(f.Imports) < 3 {
		if importMap["kernel32.dll"] {
			return "AutoIt Script"
		}
		return "AutoIt/Resource Script"
	}

	// Haskell detection (if present)
	if importMap["libhs-ghc.dll"] || importMap["libhsrts.dll"] {
		return "Haskell"
	}

	// Fortran detection
	if importMap["libifcoremmd.dll"] || importMap["libmmd.dll"] {
		return "Fortran (Intel/GCC)"
	}

	// Nim detection
	if importMap["nim.dll"] || sectionNames[".nims"] {
		return "Nim"
	}

	// Crystal detection
	if importMap["crystal.dll"] || sectionNames[".crystal"] {
		return "Crystal"
	}

	// Ada detection
	if importMap["libgnat"] || importMap["gnatlib.dll"] {
		return "Ada (GNAT)"
	}

	// Julia detection
	if importMap["libjulia.dll"] || sectionNames[".julia"] {
		return "Julia"
	}

	// D detection
	if importMap["phobos.dll"] || sectionNames[".dmodules"] {
		return "D (dlang)"
	}

	// Swift detection
	if importMap["swiftrt.dll"] || sectionNames[".swift"] {
		return "Swift"
	}

	// Erlang/Elixir detection
	if importMap["erl_nif.dll"] {
		return "Erlang/Elixir"
	}

	// Generic C/C++ detection
	if importMap["kernel32.dll"] || importMap["ntdll.dll"] {
		if importMap["user32.dll"] || importMap["gdi32.dll"] || importMap["advapi32.dll"] {
			return "C/C++ (Windows Native)"
		}
		if sectionNames[".text"] && sectionNames[".data"] {
			return "C/C++"
		}
	}

	// Delphi generic detection
	if importMap["kernel32.dll"] && len(f.Imports) > 15 {
		return "Delphi (likely)"
	}

	// Assembly or UPX packed
	if sectionNames["upx0"] || sectionNames["upx1"] {
		return "UPX Packed (Original: Unknown)"
	}

	// Dotfuscator obfuscation
	if sectionNames[".obfuscated"] {
		return ".NET (Obfuscated)"
	}

	// Windows kernel driver
	if sectionNames[".reloc"] && !importMap["kernel32.dll"] && len(f.Imports) < 3 {
		return "Windows Driver"
	}

	// Large number of imports suggests higher-level language
	if len(f.Imports) > 20 {
		return "Compiled Application (Complex dependencies)"
	}

	// No imports or very few
	if len(f.Imports) == 0 {
		if len(f.Sections) > 6 {
			return "Statically Linked Binary"
		}
		return "Unknown (No imports)"
	}

	if len(f.Imports) > 0 {
		return "Unknown (likely compiled)"
	}

	return "Unknown"
}

func extractStrings(filename string, minLen int, outFilename string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	results := extractStringsData(b, minLen)

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

func extractStringsData(b []byte, minLen int) []string {
	var results []string

	var cur []byte
	for _, c := range b {
		if c >= 32 && c <= 126 {
			cur = append(cur, c)
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

	return results
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
		fmt.Printf("No imports found in %s\n", filename)
		return nil
	}

	for _, imp := range f.Imports {
		fmt.Printf("DLL: %s\n", imp.Name)
		for _, e := range imp.Functions {
			if e.Name != "" {
				fmt.Printf("  -> %s\n", e.Name)
			} else {
				fmt.Printf("  -> ord: %d\n", e.Ordinal)
			}
		}
	}

	return nil
}

func debugInfo(filename string) error {
	f, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		return fmt.Errorf("error opening PE: %w", err)
	}
	if err := f.Parse(); err != nil {
		return fmt.Errorf("error parsing PE: %w", err)
	}

	fmt.Printf("Debug info for %s:\n", filename)
	fmt.Println("--------------------------------------")

	if len(f.Debugs) == 0 {
		fmt.Println("No debug information found")
		fmt.Println("--------------------------------------")
		return nil
	}

	fmt.Printf("Number of debug entries: %d\n\n", len(f.Debugs))

	// Display each debug entry
	for idx, dbg := range f.Debugs {
		fmt.Printf("Debug Entry %d:\n", idx+1)
		fmt.Printf("  Type:              %s\n", dbg.Type)
		fmt.Printf("  Characteristics:   0x%x\n", dbg.Struct.Characteristics)
		fmt.Printf("  TimeDateStamp:     %d (0x%x)\n", dbg.Struct.TimeDateStamp, dbg.Struct.TimeDateStamp)
		fmt.Printf("  MajorVersion:      %d\n", dbg.Struct.MajorVersion)
		fmt.Printf("  MinorVersion:      %d\n", dbg.Struct.MinorVersion)
		fmt.Printf("  PointerToRawData:  0x%x\n", dbg.Struct.PointerToRawData)
		fmt.Printf("  SizeOfData:        %d bytes\n", dbg.Struct.SizeOfData)
		fmt.Printf("  AddressOfRawData:  0x%x\n", dbg.Struct.AddressOfRawData)

		// Specific handling for common debug types
		switch dbg.Type {
		case "IMAGE_DEBUG_TYPE_CODEVIEW":
			fmt.Println("  -> CodeView (PDB) format detected")
		case "IMAGE_DEBUG_TYPE_EXPORT_TABLE":
			fmt.Println("  -> Export table debug info")
		case "IMAGE_DEBUG_TYPE_FPO":
			fmt.Println("  -> Frame Pointer Omission (FPO) info")
		case "IMAGE_DEBUG_TYPE_MISC":
			fmt.Println("  -> Miscellaneous debug info")
		case "IMAGE_DEBUG_TYPE_POGO":
			fmt.Println("  -> Profile Guided Optimization (PGO) info")
		case "IMAGE_DEBUG_TYPE_EMBEDDED_MSIL":
			fmt.Println("  -> Embedded MSIL debug info")
		}
		fmt.Println()
	}

	fmt.Println("--------------------------------------")
	return nil
}

func viewHex(filename string, offset int64, size int64) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("error stat file: %w", err)
	}

	fileSize := fi.Size()
	if offset >= fileSize {
		return fmt.Errorf("offset is beyond file size")
	}

	if size <= 0 {
		size = 256
	}

	if offset+size > fileSize {
		size = fileSize - offset
	}

	if _, err := f.Seek(offset, 0); err != nil {
		return fmt.Errorf("error seeking: %w", err)
	}

	data := make([]byte, size)
	n, err := f.Read(data)
	if err != nil && err != io.EOF {
		return fmt.Errorf("error reading: %w", err)
	}

	fmt.Printf("Hex dump for %s (offset: 0x%x, size: %d bytes)\n", filename, offset, n)
	fmt.Println("--------------------------------------")

	for i := 0; i < n; i += 16 {
		end := i + 16
		if end > n {
			end = n
		}

		fmt.Printf("0x%08x: ", offset+int64(i))

		// Print hex bytes
		for j := i; j < end; j++ {
			fmt.Printf("%02x ", data[j])
		}

		// Padding for alignment
		for j := end - i; j < 16; j++ {
			fmt.Print("   ")
		}

		fmt.Print(" | ")

		// Print ASCII representation
		for j := i; j < end; j++ {
			c := data[j]
			if c >= 32 && c <= 126 {
				fmt.Printf("%c", c)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println()
	}

	fmt.Println("--------------------------------------")
	return nil
}

func writeHexData(filename string, offset int64, data []byte) error {
	f, err := os.OpenFile(filename, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer f.Close()

	if _, err := f.Seek(offset, 0); err != nil {
		return fmt.Errorf("error seeking: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("error writing: %w", err)
	}

	return nil
}

func writeHex(filename string, offset int64, hexStr string) error {
	// Parse hex string
	parts := strings.Fields(hexStr)
	data := make([]byte, 0, len(parts))

	for _, part := range parts {
		var b byte
		if _, err := fmt.Sscanf(part, "%x", &b); err != nil {
			return fmt.Errorf("invalid hex value '%s': %w", part, err)
		}
		data = append(data, b)
	}

	f, err := os.OpenFile(filename, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer f.Close()

	if _, err := f.Seek(offset, 0); err != nil {
		return fmt.Errorf("error seeking: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("error writing: %w", err)
	}

	return nil
}

func main() {

	if len(os.Args) == 1 {
		help()
		os.Exit(1)
	}

	if len(os.Args) == 2 {
		flag := strings.ToLower(os.Args[1])

		// Check for web flag
		if flag == "-w" || flag == "--web" {
			if err := RunWebUI(); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			return
		}

		// Check for help flag
		if flag == "-h" || flag == "--help" {
			help()
			return
		}

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

	flag := strings.ToLower(os.Args[1])
	filename := os.Args[2]

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

	case "-d", "--debug":
		if err := debugInfo(filename); err != nil {
			fmt.Printf("Debug info extraction error: %v\n", err)
			os.Exit(1)
		}

	case "--hex":
		if len(os.Args) < 4 {
			fmt.Println("Usage: analyzer --hex <file> <offset> [size]")
			os.Exit(1)
		}
		filename := os.Args[2]
		var offset, size int64
		if _, err := fmt.Sscanf(os.Args[3], "%x", &offset); err != nil {
			if _, err := fmt.Sscanf(os.Args[3], "%d", &offset); err != nil {
				fmt.Printf("Invalid offset: %v\n", err)
				os.Exit(1)
			}
		}
		size = 256
		if len(os.Args) >= 5 {
			if _, err := fmt.Sscanf(os.Args[4], "%x", &size); err != nil {
				if _, err := fmt.Sscanf(os.Args[4], "%d", &size); err != nil {
					fmt.Printf("Invalid size: %v\n", err)
					os.Exit(1)
				}
			}
		}
		if err := viewHex(filename, offset, size); err != nil {
			fmt.Printf("Hex view error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown option: %s\n", flag)
		help()
	}
}
