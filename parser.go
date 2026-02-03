package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// DOS Header - структура заголовка DOS (64 байта)
type DOSHeader struct {
	Signature  [2]byte  // Offset 0x00: "MZ"
	LastPage   uint16   // Offset 0x02
	PageCount  uint16   // Offset 0x04
	ReloCnt    uint16   // Offset 0x06
	HdrSize    uint16   // Offset 0x08
	MinExtra   uint16   // Offset 0x0A
	MaxExtra   uint16   // Offset 0x0C
	InitSS     uint16   // Offset 0x0E
	InitSP     uint16   // Offset 0x10
	CheckSum   uint16   // Offset 0x12
	InitIP     uint16   // Offset 0x14
	InitCS     uint16   // Offset 0x16
	ReloAddr   uint16   // Offset 0x18
	OverlayNum uint16   // Offset 0x1A
	ReservedA  [8]byte  // Offset 0x1C: Зарезервировано
	OemID      uint16   // Offset 0x24
	OemInfo    uint16   // Offset 0x26
	ReservedB  [20]byte // Offset 0x28
	PEOffset   uint32   // Offset 0x3C: Смещение на NT заголовок
}

// NT Header Signature - сигнатура NT заголовка
type NTSignature struct {
	Signature [4]byte // "PE\0\0"
}

// File Header - файловый заголовок
type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// Optional Header - опциональный заголовок (32-bit)
type OptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

// Optional Header - опциональный заголовок (64-bit)
type OptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

// Section Header - заголовок секции
type SectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// PEParser - парсер PE файлов
type PEParser struct {
	filePath         string
	file             *os.File
	reader           *bytes.Reader
	data             []byte
	DOSHeader        *DOSHeader
	NTSignature      *NTSignature
	FileHeader       *FileHeader
	OptionalHeader32 *OptionalHeader32
	OptionalHeader64 *OptionalHeader64
	SectionHeaders   []SectionHeader
	Is64Bit          bool
}

// NewPEParser - создает новый парсер PE файла
func NewPEParser(filePath string) (*PEParser, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}

	parser := &PEParser{
		filePath: filePath,
		data:     data,
		reader:   bytes.NewReader(data),
	}

	return parser, nil
}

// Parse - парсит PE структуру
func (p *PEParser) Parse() error {
	// Парсим DOS заголовок
	if err := p.parseDOSHeader(); err != nil {
		return err
	}

	// Парсим NT заголовки
	if err := p.parseNTHeaders(); err != nil {
		return err
	}

	// Парсим заголовки секций
	if err := p.parseSectionHeaders(); err != nil {
		return err
	}

	return nil
}

// parseDOSHeader - парсит DOS заголовок
func (p *PEParser) parseDOSHeader() error {
	p.reader.Seek(0, io.SeekStart)
	p.DOSHeader = &DOSHeader{}

	if err := binary.Read(p.reader, binary.LittleEndian, p.DOSHeader); err != nil {
		return fmt.Errorf("ошибка парсинга DOS заголовка: %w", err)
	}

	// Проверяем сигнатуру MZ
	if p.DOSHeader.Signature != [2]byte{'M', 'Z'} {
		return fmt.Errorf("некорректная сигнатура DOS заголовка: %s", string(p.DOSHeader.Signature[:]))
	}

	return nil
}

// parseNTHeaders - парсит NT заголовки (сигнатура, файловый и опциональный)
func (p *PEParser) parseNTHeaders() error {
	// Переходим на NT заголовок
	p.reader.Seek(int64(p.DOSHeader.PEOffset), io.SeekStart)

	// Парсим сигнатуру PE
	p.NTSignature = &NTSignature{}
	if err := binary.Read(p.reader, binary.LittleEndian, p.NTSignature); err != nil {
		return fmt.Errorf("ошибка парсинга сигнатуры PE: %w", err)
	}

	if p.NTSignature.Signature != [4]byte{'P', 'E', 0, 0} {
		return fmt.Errorf("некорректная сигнатура PE: %v", p.NTSignature.Signature)
	}

	// Парсим файловый заголовок
	p.FileHeader = &FileHeader{}
	if err := binary.Read(p.reader, binary.LittleEndian, p.FileHeader); err != nil {
		return fmt.Errorf("ошибка парсинга файлового заголовка: %w", err)
	}

	// Определяем 32 или 64-bit на основе Magic из опционального заголовка
	currentPos, _ := p.reader.Seek(0, io.SeekCurrent)
	var magic uint16
	if err := binary.Read(p.reader, binary.LittleEndian, &magic); err != nil {
		return fmt.Errorf("ошибка чтения magic: %w", err)
	}
	p.reader.Seek(currentPos, io.SeekStart)

	p.Is64Bit = (magic == 0x20b) // PE32+ magic

	// Парсим опциональный заголовок
	if p.Is64Bit {
		p.OptionalHeader64 = &OptionalHeader64{}
		if err := binary.Read(p.reader, binary.LittleEndian, p.OptionalHeader64); err != nil {
			return fmt.Errorf("ошибка парсинга опционального заголовка 64-bit: %w", err)
		}
	} else {
		p.OptionalHeader32 = &OptionalHeader32{}
		if err := binary.Read(p.reader, binary.LittleEndian, p.OptionalHeader32); err != nil {
			return fmt.Errorf("ошибка парсинга опционального заголовка 32-bit: %w", err)
		}
	}

	return nil
}

// parseSectionHeaders - парсит заголовки секций
func (p *PEParser) parseSectionHeaders() error {
	p.SectionHeaders = make([]SectionHeader, p.FileHeader.NumberOfSections)

	for i := 0; i < int(p.FileHeader.NumberOfSections); i++ {
		if err := binary.Read(p.reader, binary.LittleEndian, &p.SectionHeaders[i]); err != nil {
			return fmt.Errorf("ошибка парсинга заголовка секции %d: %w", i, err)
		}
	}

	return nil
}

// GetSectionData - читает данные секции
func (p *PEParser) GetSectionData(sectionIndex int) ([]byte, error) {
	if sectionIndex >= len(p.SectionHeaders) {
		return nil, fmt.Errorf("индекс секции %d вне границ", sectionIndex)
	}

	section := p.SectionHeaders[sectionIndex]
	if section.SizeOfRawData == 0 {
		return []byte{}, nil
	}

	offset := section.PointerToRawData
	size := section.SizeOfRawData

	if offset+size > uint32(len(p.data)) {
		return nil, fmt.Errorf("секция выходит за границы файла")
	}

	return p.data[offset : offset+size], nil
}

// GetSectionByName - получает секцию по имени
func (p *PEParser) GetSectionByName(name string) *SectionHeader {
	for i := range p.SectionHeaders {
		sectionName := bytes.TrimRight(p.SectionHeaders[i].Name[:], "\x00")
		if string(sectionName) == name {
			return &p.SectionHeaders[i]
		}
	}
	return nil
}

// PrintDOSHeader - выводит информацию о DOS заголовке
func (p *PEParser) PrintDOSHeader() {
	fmt.Println("=== DOS HEADER ===")
	fmt.Printf("Signature:          %s\n", string(p.DOSHeader.Signature[:]))
	fmt.Printf("PE Offset:          0x%08x (%d)\n", p.DOSHeader.PEOffset, p.DOSHeader.PEOffset)
	fmt.Printf("Last Page:          %d\n", p.DOSHeader.LastPage)
	fmt.Printf("Page Count:         %d\n", p.DOSHeader.PageCount)
	fmt.Printf("Header Size:        %d paragraphs\n", p.DOSHeader.HdrSize)
	fmt.Println()
}

// PrintNTHeaders - выводит информацию о NT заголовках
func (p *PEParser) PrintNTHeaders() {
	fmt.Println("=== NT HEADERS ===")

	// Сигнатура
	fmt.Printf("Signature:          %s\n", string(p.NTSignature.Signature[:]))

	// File Header
	fmt.Println("\n--- File Header ---")
	fmt.Printf("Machine:            0x%04x\n", p.FileHeader.Machine)
	fmt.Printf("Number of Sections: %d\n", p.FileHeader.NumberOfSections)
	fmt.Printf("TimeDateStamp:      %d\n", p.FileHeader.TimeDateStamp)
	fmt.Printf("Characteristics:    0x%04x\n", p.FileHeader.Characteristics)

	// Optional Header
	fmt.Println("\n--- Optional Header ---")
	if p.Is64Bit {
		fmt.Printf("Magic:              0x%04x (PE32+/64-bit)\n", p.OptionalHeader64.Magic)
		fmt.Printf("Image Base:         0x%016x\n", p.OptionalHeader64.ImageBase)
		fmt.Printf("Entry Point:        0x%08x\n", p.OptionalHeader64.AddressOfEntryPoint)
		fmt.Printf("Size of Image:      0x%08x (%d bytes)\n", p.OptionalHeader64.SizeOfImage, p.OptionalHeader64.SizeOfImage)
		fmt.Printf("Size of Headers:    0x%08x (%d bytes)\n", p.OptionalHeader64.SizeOfHeaders, p.OptionalHeader64.SizeOfHeaders)
		fmt.Printf("Subsystem:          0x%04x\n", p.OptionalHeader64.Subsystem)
		fmt.Printf("Section Alignment:  0x%08x\n", p.OptionalHeader64.SectionAlignment)
		fmt.Printf("File Alignment:     0x%08x\n", p.OptionalHeader64.FileAlignment)
	} else {
		fmt.Printf("Magic:              0x%04x (PE32/32-bit)\n", p.OptionalHeader32.Magic)
		fmt.Printf("Image Base:         0x%08x\n", p.OptionalHeader32.ImageBase)
		fmt.Printf("Entry Point:        0x%08x\n", p.OptionalHeader32.AddressOfEntryPoint)
		fmt.Printf("Size of Image:      0x%08x (%d bytes)\n", p.OptionalHeader32.SizeOfImage, p.OptionalHeader32.SizeOfImage)
		fmt.Printf("Size of Headers:    0x%08x (%d bytes)\n", p.OptionalHeader32.SizeOfHeaders, p.OptionalHeader32.SizeOfHeaders)
		fmt.Printf("Subsystem:          0x%04x\n", p.OptionalHeader32.Subsystem)
		fmt.Printf("Section Alignment:  0x%08x\n", p.OptionalHeader32.SectionAlignment)
		fmt.Printf("File Alignment:     0x%08x\n", p.OptionalHeader32.FileAlignment)
	}
	fmt.Println()
}

// PrintSectionHeaders - выводит информацию о заголовках секций
func (p *PEParser) PrintSectionHeaders() {
	fmt.Println("=== SECTION HEADERS ===")
	fmt.Printf("%-10s %-12s %-12s %-12s %-12s %s\n", "Name", "VirtSize", "VirtAddr", "RawSize", "RawAddr", "Characteristics")
	fmt.Println("-----------------------------------------------------------------------")

	for _, section := range p.SectionHeaders {
		name := bytes.TrimRight(section.Name[:], "\x00")
		if len(name) == 0 {
			name = []byte("(empty)")
		}
		fmt.Printf("%-10s 0x%08x   0x%08x   0x%08x   0x%08x   0x%08x\n",
			string(name),
			section.VirtualSize,
			section.VirtualAddress,
			section.SizeOfRawData,
			section.PointerToRawData,
			section.Characteristics)
	}
	fmt.Println()
}

// PrintSectionData - выводит данные секции в hex формате
func (p *PEParser) PrintSectionData(sectionIndex int, limit int) error {
	if sectionIndex >= len(p.SectionHeaders) {
		return fmt.Errorf("индекс секции %d вне границ", sectionIndex)
	}

	section := p.SectionHeaders[sectionIndex]
	sectionNameBytes := bytes.TrimRight(section.Name[:], "\x00")
	sectionName := string(sectionNameBytes)
	if len(sectionName) == 0 {
		sectionName = fmt.Sprintf("Section[%d]", sectionIndex)
	}

	data, err := p.GetSectionData(sectionIndex)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		fmt.Printf("Секция %s пуста\n", sectionName)
		return nil
	}

	if limit > 0 && len(data) > limit {
		data = data[:limit]
	}

	fmt.Printf("=== Section: %s (first %d bytes) ===\n", sectionName, len(data))
	fmt.Print(hexDump(data, 0))
	fmt.Println()

	return nil
}

// hexDump - форматирует данные в hex формате
func hexDump(data []byte, offset int64) string {
	var result string
	for i := 0; i < len(data); i += 16 {
		result += fmt.Sprintf("%08x  ", offset+int64(i))

		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result += fmt.Sprintf("%02x ", data[i+j])
			} else {
				result += "   "
			}
		}

		result += " "
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				result += string(b)
			} else {
				result += "."
			}
		}
		result += "\n"
	}
	return result
}
