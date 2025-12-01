package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	peparser "github.com/saferwall/pe"
)

func usage() {
	fmt.Println("Usage: analyze-pe <file.exe|file.dll>")
	fmt.Println("Provide a PE executable or DLL to analyze.")
}

func isSupportedBinary(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".drv"
}

// Config для анализа строк
type StringConfig struct {
	MinLength   int
	IncludeCode bool // Включать ли строки из секции кода (.text)
	OnlyAscii   bool // Только ASCII строки
}

// PEAnalyzer для анализа PE файлов
type PEAnalyzer struct {
	Config StringConfig
	PE     *peparser.File
}

// NewPEAnalyzer создает новый анализатор
func NewPEAnalyzer(pe *peparser.File, config StringConfig) *PEnalyzer {
	return &PEAnalyzer{
		Config: config,
		PE:     pe,
	}
}

// extractStringsFromRawFile извлекает строки из сырого файла
func extractStringsFromRawFile(filename string, minLength int) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var stringsFound []string
	var current []byte

	for _, b := range data {
		// Проверка на печатные ASCII символы
		if b >= 32 && b <= 126 {
			current = append(current, b)
		} else {
			if len(current) >= minLength {
				str := string(current)
				if isValidAsciiString(str) {
					stringsFound = append(stringsFound, str)
				}
			}
			current = nil
		}
	}

	// Последняя строка
	if len(current) >= minLength {
		str := string(current)
		if isValidAsciiString(str) {
			stringsFound = append(stringsFound, str)
		}
	}

	return stringsFound, nil
}

// isValidAsciiString проверяет, является ли строка содержательной
func isValidAsciiString(s string) bool {
	if len(s) < 3 {
		return false
	}

	// Проверка на hex дамп
	hexOnly := true
	hasLetters := false
	hasSpaces := false

	for _, r := range s {
		if !((r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'f') ||
			(r >= 'A' && r <= 'F') ||
			r == 'x' || r == 'X') {
			hexOnly = false
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetters = true
		}
		if r == ' ' || r == '\t' {
			hasSpaces = true
		}
	}

	// Фильтр случайных последовательностей
	if hexOnly && len(s) > 6 {
		return false
	}

	// Должны быть буквы или пробелы для длинных строк
	if len(s) > 10 && !hasLetters && !hasSpaces {
		return false
	}

	return true
}

// extractStringsFromSections извлекает строки из секций PE
func (a *PEAnalyzer) extractStringsFromSections() ([]string, error) {
	var allStrings []string

	for _, section := range a.PE.Sections {
		// Пропускаем секцию кода если не включено
		if !a.Config.IncludeCode && (section.Header.Name == ".text" ||
			strings.Contains(section.Header.Name, "CODE")) {
			continue
		}

		// Читаем данные секции
		data, err := section.Data()
		if err != nil {
			continue
		}

		// Извлекаем строки из данных секции
		sectionStrings := a.extractStringsFromData(data)
		allStrings = append(allStrings, sectionStrings...)
	}

	return allStrings, nil
}

// extractStringsFromData извлекает строки из массива байт
func (a *PEAnalyzer) extractStringsFromData(data []byte) []string {
	var stringsFound []string
	var current []byte

	for _, b := range data {
		// Проверка символов в зависимости от конфигурации
		if a.Config.OnlyAscii {
			if b >= 32 && b <= 126 {
				current = append(current, b)
			} else {
				if len(current) >= a.Config.MinLength {
					str := string(current)
					if isValidAsciiString(str) {
						stringsFound = append(stringsFound, str)
					}
				}
				current = nil
			}
		} else {
			// Расширенный диапазон для UTF-8
			if (b >= 32 && b <= 126) || (b >= 0xC0 && b <= 0xFF) {
				current = append(current, b)
			} else {
				if len(current) >= a.Config.MinLength {
					str := string(current)
					if utf8.ValidString(str) && isValidStringExtended(str) {
						stringsFound = append(stringsFound, str)
					}
				}
				current = nil
			}
		}
	}

	// Последняя строка
	if len(current) >= a.Config.MinLength {
		str := string(current)
		if a.Config.OnlyAscii {
			if isValidAsciiString(str) {
				stringsFound = append(stringsFound, str)
			}
		} else {
			if utf8.ValidString(str) && isValidStringExtended(str) {
				stringsFound = append(stringsFound, str)
			}
		}
	}

	return stringsFound
}

// isValidStringExtended расширенная проверка строк
func isValidStringExtended(s string) bool {
	// Минимальная длина
	if len(s) < 4 {
		return false
	}

	// Проверяем что строка содержит осмысленные символы
	hasLetters := false
	hasPrintable := false
	consecutivePrintable := 0
	maxConsecutive := 0

	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetters = true
			consecutivePrintable++
		} else if r >= '0' && r <= '9' {
			consecutivePrintable++
		} else if r == ' ' || r == '_' || r == '-' || r == '.' || r == ',' ||
			r == ':' || r == ';' || r == '!' || r == '?' || r == '/' || r == '\\' ||
			r == '@' || r == '#' || r == '$' || r == '%' || r == '&' || r == '*' ||
			r == '(' || r == ')' || r == '[' || r == ']' || r == '{' || r == '}' ||
			r == '<' || r == '>' || r == '+' || r == '=' || r == '|' || r == '~' ||
			r == '`' || r == '\'' || r == '"' {
			hasPrintable = true
			consecutivePrintable++
		} else {
			if consecutivePrintable > maxConsecutive {
				maxConsecutive = consecutivePrintable
			}
			consecutivePrintable = 0
		}
	}

	if consecutivePrintable > maxConsecutive {
		maxConsecutive = consecutivePrintable
	}

	// Должен быть достаточно длинный непрерывный участок печатных символов
	if maxConsecutive < 4 {
		return false
	}

	// Для очень длинных строк требуем буквы
	if len(s) > 15 && !hasLetters {
		return false
	}

	return true
}

// extractStringsFromResources извлекает строки из ресурсов
func (a *PEAnalyzer) extractStringsFromResources() ([]string, error) {
	var stringsFound []string

	if a.PE.Resources == nil {
		return stringsFound, nil
	}

	// Обходим дерево ресурсов
	var traverseResources func(resources []*peparser.ResourceDataEntry)
	traverseResources = func(entries []*peparser.ResourceDataEntry) {
		for _, entry := range entries {
			// Проверяем тип ресурса
			if entry.Type == 6 { // RT_STRING (6)
				// Обрабатываем строковые ресурсы
				if entry.Data != nil {
					strs := a.extractUnicodeStrings(entry.Data)
					stringsFound = append(stringsFound, strs...)
				}
			}

			// Рекурсивно обходим подкаталоги
			if entry.Subdirectory != nil {
				traverseResources(entry.Subdirectory)
			}
		}
	}

	traverseResources(a.PE.Resources.Entries)
	return stringsFound, nil
}

// extractUnicodeStrings извлекает Unicode строки из данных
func (a *PEAnalyzer) extractUnicodeStrings(data []byte) []string {
	var stringsFound []string

	// Обработка UTF-16LE строк
	i := 0
	for i < len(data) {
		// Читаем длину строки (2 байта)
		if i+2 > len(data) {
			break
		}
		length := int(uint16(data[i]) | uint16(data[i+1])<<8)
		i += 2

		if length == 0 {
			continue
		}

		// Читаем саму строку
		if i+length*2 > len(data) {
			break
		}

		// Конвертируем UTF-16LE в UTF-8
		runes := make([]rune, length)
		for j := 0; j < length; j++ {
			if i+2 > len(data) {
				break
			}
			code := uint16(data[i]) | uint16(data[i+1])<<8
			runes[j] = rune(code)
			i += 2
		}

		str := string(runes)
		if len(str) >= a.Config.MinLength && isValidStringExtended(str) {
			stringsFound = append(stringsFound, str)
		}
	}

	return stringsFound
}

// extractImportExportStrings извлекает строки из импорта/экспорта
func (a *PEAnalyzer) extractImportExportStrings() []string {
	var stringsFound []string

	// Имена импортируемых функций
	if a.PE.Imports != nil {
		for _, imp := range a.PE.Imports {
			if imp.Name != "" && len(imp.Name) >= a.Config.MinLength {
				stringsFound = append(stringsFound, imp.Name)
			}
			for _, funcImp := range imp.Functions {
				if funcImp.Name != "" && len(funcImp.Name) >= a.Config.MinLength {
					stringsFound = append(stringsFound, funcImp.Name)
				}
			}
		}
	}

	// Имена экспортируемых функций
	if a.PE.Exports != nil {
		for _, exp := range a.PE.Exports.Functions {
			if exp.Name != "" && len(exp.Name) >= a.Config.MinLength {
				stringsFound = append(stringsFound, exp.Name)
			}
		}
	}

	return stringsFound
}

// uniqueStrings удаляет дубликаты из списка строк
func uniqueStrings(strings []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, s := range strings {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// analyzeStrings выполняет полный анализ строк
func analyzeStrings(filename string, pe *peparser.File) error {
	// Конфигурация по умолчанию
	config := StringConfig{
		MinLength:   4,
		IncludeCode: false,
		OnlyAscii:   true,
	}

	analyzer := NewPEAnalyzer(pe, config)

	// 1. Извлечение строк из сырого файла
	fmt.Println("\n=== Strings from raw file ===")
	rawStrings, err := extractStringsFromRawFile(filename, config.MinLength)
	if err != nil {
		log.Printf("Error extracting raw strings: %v", err)
	} else {
		rawStrings = uniqueStrings(rawStrings)
		for i, s := range rawStrings {
			if i < 20 { // Показываем первые 20 строк
				fmt.Printf("%d: %s\n", i+1, s)
			}
		}
		if len(rawStrings) > 20 {
			fmt.Printf("... and %d more strings\n", len(rawStrings)-20)
		}
	}

	// 2. Извлечение строк из секций
	fmt.Println("\n=== Strings from PE sections ===")
	sectionStrings, err := analyzer.extractStringsFromSections()
	if err != nil {
		log.Printf("Error extracting section strings: %v", err)
	} else {
		sectionStrings = uniqueStrings(sectionStrings)
		for i, s := range sectionStrings {
			if i < 20 {
				fmt.Printf("%d: %s\n", i+1, s)
			}
		}
		if len(sectionStrings) > 20 {
			fmt.Printf("... and %d more strings\n", len(sectionStrings)-20)
		}
	}

	// 3. Извлечение строк из ресурсов
	fmt.Println("\n=== Strings from resources ===")
	resourceStrings, err := analyzer.extractStringsFromResources()
	if err != nil {
		log.Printf("Error extracting resource strings: %v", err)
	} else {
		resourceStrings = uniqueStrings(resourceStrings)
		for i, s := range resourceStrings {
			if i < 20 {
				fmt.Printf("%d: %s\n", i+1, s)
			}
		}
		if len(resourceStrings) > 20 {
			fmt.Printf("... and %d more strings\n", len(resourceStrings)-20)
		}
	}

	// 4. Извлечение строк из импорта/экспорта
	fmt.Println("\n=== Import/Export strings ===")
	importExportStrings := analyzer.extractImportExportStrings()
	importExportStrings = uniqueStrings(importExportStrings)
	for i, s := range importExportStrings {
		if i < 20 {
			fmt.Printf("%d: %s\n", i+1, s)
		}
	}

	// 5. Сводная статистика
	fmt.Println("\n=== String Analysis Summary ===")
	fmt.Printf("Raw strings: %d\n", len(rawStrings))
	fmt.Printf("Section strings: %d\n", len(sectionStrings))
	fmt.Printf("Resource strings: %d\n", len(resourceStrings))
	fmt.Printf("Import/Export strings: %d\n", len(importExportStrings))

	// Объединяем все строки (уникальные)
	allStrings := append(rawStrings, sectionStrings...)
	allStrings = append(allStrings, resourceStrings...)
	allStrings = append(allStrings, importExportStrings...)
	allStrings = uniqueStrings(allStrings)

	fmt.Printf("\nTotal unique strings: %d\n", len(allStrings))

	// Сохраняем в файл
	outputFile := filename + ".strings.txt"
	err = saveStringsToFile(allStrings, outputFile)
	if err != nil {
		log.Printf("Error saving strings to file: %v", err)
	} else {
		fmt.Printf("Strings saved to: %s\n", outputFile)
	}

	return nil
}

// saveStringsToFile сохраняет строки в файл
func saveStringsToFile(strings []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, s := range strings {
		_, err := file.WriteString(s + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}

// analyzePEStructure анализирует структуру PE файла
func analyzePEStructure(pe *peparser.File) {
	fmt.Println("\n=== PE Structure Analysis ===")

	// Заголовки
	fmt.Printf("Architecture: %s\n", pe.NtHeader.FileHeader.Machine)
	fmt.Printf("Number of Sections: %d\n", pe.NtHeader.FileHeader.NumberOfSections)
	fmt.Printf("Characteristics: 0x%X\n", pe.NtHeader.FileHeader.Characteristics)

	// Секции
	fmt.Println("\n=== Sections ===")
	for i, section := range pe.Sections {
		fmt.Printf("%d. %s: Size=0x%X, VirtualSize=0x%X, Characteristics=0x%X\n",
			i+1, section.Header.Name,
			section.Header.SizeOfRawData,
			section.Header.VirtualSize,
			section.Header.Characteristics)
	}

	// Импорты
	if pe.Imports != nil {
		fmt.Println("\n=== Imports ===")
		for i, imp := range pe.Imports {
			fmt.Printf("%d. %s (%d functions)\n", i+1, imp.Name, len(imp.Functions))
		}
	}

	// Экспорты
	if pe.Exports != nil {
		fmt.Println("\n=== Exports ===")
		fmt.Printf("Library: %s\n", pe.Exports.Name)
		fmt.Printf("Number of functions: %d\n", len(pe.Exports.Functions))
	}

	// Ресурсы
	if pe.Resources != nil {
		fmt.Println("\n=== Resources ===")
		fmt.Printf("Number of resource entries: %d\n", len(pe.Resources.Entries))
	}
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

	analyzePEStructure(pe)

	err = analyzeStrings(filename, pe)
	if err != nil {
		log.Printf("Error analyzing strings: %v", err)
	}
}
