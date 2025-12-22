package main

import (
	"bytes"
	"fmt"
	"image/color"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type CustomTheme struct{}

func (CustomTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0x1e, G: 0x1e, B: 0x1e, A: 0xff}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0x64, G: 0xb5, B: 0xf6, A: 0xff}
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0xff, G: 0xb7, B: 0x4d, A: 0xff}
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 0x90, G: 0x90, B: 0x90, A: 0xff}
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x64, G: 0xb5, B: 0xf6, A: 0x55}
	}
	return theme.DefaultTheme().Color(name, variant)
}

func (CustomTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (CustomTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (CustomTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

type AnalyzerUI struct {
	app          fyne.App
	window       fyne.Window
	filePath     *widget.Label
	fullFilePath string
	output       *widget.RichText
	statusBar    *widget.Label
	outputBuf    *bytes.Buffer
}

type HexEditor struct {
	filePath     string
	data         []byte
	offset       int64
	hexEntries   []*widget.Entry // Entry fields для каждого байта
	asciiEntry   *widget.Entry
	offsetLabel  *widget.Label
	modified     bool
	startAddr    int64
	mainApp      fyne.App
	hexDisplay   *widget.RichText
	hexContainer *fyne.Container // Container для редактируемых полей
}

func NewAnalyzerUI() *AnalyzerUI {
	myApp := app.NewWithID("com.analyzer.peanalyzer")
	myApp.Settings().SetTheme(CustomTheme{})
	myWindow := myApp.NewWindow("PE Analyzer")
	myWindow.Resize(fyne.NewSize(1200, 800))

	return &AnalyzerUI{
		app:          myApp,
		window:       myWindow,
		output:       widget.NewRichTextFromMarkdown(""),
		outputBuf:    new(bytes.Buffer),
		fullFilePath: "",
	}
}

func (ui *AnalyzerUI) Run() {
	headerBg := canvas.NewRectangle(color.NRGBA{R: 0x29, G: 0x2d, B: 0x3e, A: 0xff})
	headerBg.SetMinSize(fyne.NewSize(1200, 70))

	titleText := canvas.NewText("🔍 PE Analyzer", color.White)
	titleText.TextSize = 28
	titleText.TextStyle.Bold = true

	subtitleText := canvas.NewText("Advanced Portable Executable Analysis", color.NRGBA{R: 0x64, G: 0xb5, B: 0xf6, A: 0xff})
	subtitleText.TextSize = 12

	headerContainer := container.NewVBox(
		container.NewPadded(titleText),
		container.NewPadded(subtitleText),
	)

	headerStack := container.NewStack(headerBg, headerContainer)

	ui.filePath = widget.NewLabel("📁 No file selected")
	ui.filePath.Alignment = fyne.TextAlignCenter

	selectBtn := widget.NewButton("Select PE File (.exe/.dll)", ui.onSelectFile)
	selectBtn.Importance = widget.HighImportance

	fileCard := ui.createCard("1. SELECT FILE", container.NewVBox(
		ui.filePath,
		selectBtn,
	))

	basicBtn := widget.NewButton("📊 Basic Info", ui.onBasicInfo)
	importsBtn := widget.NewButton("📦 Imports", ui.onImports)
	sectionsBtn := widget.NewButton("🔧 Sections", ui.onSections)
	debugBtn := widget.NewButton("🐛 Debug Info", ui.onDebugInfo)
	stringsBtn := widget.NewButton("📄 Strings", ui.onExtractStrings)
	exportBtn := widget.NewButton("💾 Export Strings", ui.onExportStrings)
	hexViewBtn := widget.NewButton("🔍 View Hex", ui.onViewHex)
	hexEditBtn := widget.NewButton("✏️ Edit Hex", ui.onEditHex)

	buttonGrid := container.NewGridWithColumns(8,
		basicBtn, importsBtn, sectionsBtn, debugBtn, stringsBtn, exportBtn, hexViewBtn, hexEditBtn,
	)

	analysisCard := ui.createCard("2. ANALYSIS TOOLS", buttonGrid)

	ui.output.Wrapping = fyne.TextWrapWord
	outputScroll := container.NewScroll(ui.output)
	outputScroll.SetMinSize(fyne.NewSize(1100, 450))
	outputBorder := ui.createCard("3. RESULTS", outputScroll)

	ui.statusBar = widget.NewLabel("✓ Ready to analyze")
	statusBg := canvas.NewRectangle(color.NRGBA{R: 0x29, G: 0x2d, B: 0x3e, A: 0xff})
	statusContainer := container.NewStack(statusBg, ui.statusBar)

	mainContainer := container.NewVBox(
		headerStack,
		container.NewPadded(fileCard),
		container.NewPadded(analysisCard),
		container.NewPadded(outputBorder),
		statusContainer,
	)

	scroll := container.NewScroll(mainContainer)
	ui.window.SetContent(scroll)
	ui.window.ShowAndRun()
}

func (ui *AnalyzerUI) createCard(title string, content fyne.CanvasObject) fyne.CanvasObject {
	titleLabel := canvas.NewText(title, color.NRGBA{R: 0x64, G: 0xb5, B: 0xf6, A: 0xff})
	titleLabel.TextSize = 14
	titleLabel.TextStyle.Bold = true

	separator := canvas.NewLine(color.NRGBA{R: 0x64, G: 0xb5, B: 0xf6, A: 0x88})
	separator.StrokeWidth = 1

	cardBg := canvas.NewRectangle(color.NRGBA{R: 0x25, G: 0x25, B: 0x35, A: 0xff})

	innerContainer := container.NewVBox(
		titleLabel,
		separator,
		content,
	)

	return container.NewStack(cardBg, container.NewPadded(innerContainer))
}

func (ui *AnalyzerUI) redirectOutput(fn func()) string {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		return ""
	}
	os.Stdout = w
	os.Stderr = w

	ui.outputBuf.Reset()

	// Читаем из pipe в отдельной горутине
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(ui.outputBuf, r)
	}()

	// Выполняем функцию
	fn()
	w.Close()

	// Ждём завершения чтения
	<-done

	os.Stdout = oldStdout
	os.Stderr = oldStderr

	return ui.outputBuf.String()
}

func (ui *AnalyzerUI) onSelectFile() {
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil || reader == nil {
			if err != nil {
				dialog.ShowError(err, ui.window)
			}
			return
		}
		defer reader.Close()

		path := reader.URI().Path()
		path = filepath.FromSlash(path)
		path = filepath.Clean(path)
		ui.fullFilePath = path

		filename := filepath.Base(path)

		ui.filePath.SetText("📁 " + filename)
		ui.updateStatus("✓ File loaded: " + filename)
		ui.output.ParseMarkdown("")
	}, ui.window)
}

func (ui *AnalyzerUI) getFilePath() string {
	if ui.fullFilePath == "" {
		ui.updateStatus("⚠️  Select a file first")
		return ""
	}
	return ui.fullFilePath
}

func (ui *AnalyzerUI) displayOutput(title, output string, isError bool) {
	fyne.Do(func() {
		if isError {
			ui.output.ParseMarkdown(fmt.Sprintf("### ❌ Error\n```\n%s\n```", output))
		} else {
			ui.output.ParseMarkdown(fmt.Sprintf("### ✅ %s\n```\n%s\n```", title, output))
		}
	})
}

func (ui *AnalyzerUI) onBasicInfo() {
	path := ui.getFilePath()
	if path == "" {
		return
	}
	ui.updateStatus("🔄 Analyzing basic info...")
	output := ui.redirectOutput(func() { basicInfo(path) })
	if output == "" {
		ui.displayOutput("", "No output from analyzer", true)
		ui.updateStatus("❌ Analysis failed")
	} else {
		ui.displayOutput("Basic Info", output, false)
		ui.updateStatus("✓ Basic info extracted")
	}
}

func (ui *AnalyzerUI) onImports() {
	path := ui.getFilePath()
	if path == "" {
		return
	}
	ui.updateStatus("🔄 Extracting imports...")
	output := ui.redirectOutput(func() { importsPE(path) })
	if output == "" {
		ui.displayOutput("", "No output from analyzer", true)
		ui.updateStatus("❌ Extraction failed")
	} else {
		ui.displayOutput("Imports", output, false)
		ui.updateStatus("✓ Imports extracted")
	}
}

func (ui *AnalyzerUI) onSections() {
	path := ui.getFilePath()
	if path == "" {
		return
	}
	ui.updateStatus("🔄 Analyzing sections...")
	output := ui.redirectOutput(func() { sectionsPE(path) })
	if output == "" {
		ui.displayOutput("", "No output from analyzer", true)
		ui.updateStatus("❌ Analysis failed")
	} else {
		ui.displayOutput("Sections", output, false)
		ui.updateStatus("✓ Sections analyzed")
	}
}

func (ui *AnalyzerUI) onDebugInfo() {
	path := ui.getFilePath()
	if path == "" {
		return
	}
	ui.updateStatus("🔄 Extracting debug info...")
	output := ui.redirectOutput(func() { debugInfo(path) })
	if output == "" {
		ui.displayOutput("", "No output from analyzer", true)
		ui.updateStatus("❌ Extraction failed")
	} else {
		ui.displayOutput("Debug Info", output, false)
		ui.updateStatus("✓ Debug info extracted")
	}
}

func (ui *AnalyzerUI) onExtractStrings() {
	path := ui.getFilePath()
	if path == "" {
		return
	}
	ui.updateStatus("🔄 Extracting strings...")

	// Запускаем в отдельной горутине чтобы не заморозить UI
	go func() {
		output := ui.redirectOutput(func() { extractStrings(path, 4, "") })
		if output == "" {
			ui.displayOutput("", "No output from analyzer", true)
			ui.updateStatus("❌ Extraction failed")
		} else {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			maxLines := 100
			if len(lines) > maxLines {
				lines = append(lines[:maxLines], fmt.Sprintf("\n... and %d more strings", len(lines)-maxLines))
			}
			ui.displayOutput("Extracted Strings", strings.Join(lines, "\n"), false)
			ui.updateStatus(fmt.Sprintf("✓ Extracted %d strings", len(lines)))
		}
	}()
}

func (ui *AnalyzerUI) onExportStrings() {
	path := ui.getFilePath()
	if path == "" {
		return
	}
	dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		defer writer.Close()

		ui.updateStatus("🔄 Exporting strings...")
		go func() {
			if err := extractStrings(path, 4, filepath.FromSlash(writer.URI().Path())); err != nil {
				ui.updateStatus("❌ Export failed: " + err.Error())
			} else {
				ui.updateStatus("✓ Strings exported successfully")
			}
		}()
	}, ui.window)
}

func (ui *AnalyzerUI) onViewHex() {
	path := ui.getFilePath()
	if path == "" {
		return
	}

	offsetInput := widget.NewEntry()
	offsetInput.SetPlaceHolder("Offset (hex or decimal)")
	offsetInput.Text = "0"

	sizeInput := widget.NewEntry()
	sizeInput.SetPlaceHolder("Size (hex or decimal)")
	sizeInput.Text = "256"

	items := container.NewVBox(
		widget.NewLabel("Enter hex dump parameters:"),
		widget.NewLabel("Offset:"),
		offsetInput,
		widget.NewLabel("Size (bytes):"),
		sizeInput,
	)

	dialog.ShowCustomConfirm("View Hex Dump", "View", "Cancel",
		container.NewVBox(items),
		func(ok bool) {
			if !ok {
				return
			}

			ui.updateStatus("🔄 Loading hex dump...")
			go func() {
				var offset, size int64
				if _, err := fmt.Sscanf(offsetInput.Text, "%x", &offset); err != nil {
					if _, err := fmt.Sscanf(offsetInput.Text, "%d", &offset); err != nil {
						ui.displayOutput("", "Invalid offset: "+err.Error(), true)
						ui.updateStatus("❌ Invalid offset")
						return
					}
				}
				if _, err := fmt.Sscanf(sizeInput.Text, "%x", &size); err != nil {
					if _, err := fmt.Sscanf(sizeInput.Text, "%d", &size); err != nil {
						ui.displayOutput("", "Invalid size: "+err.Error(), true)
						ui.updateStatus("❌ Invalid size")
						return
					}
				}

				output := ui.redirectOutput(func() { viewHex(path, offset, size) })
				if output == "" {
					ui.displayOutput("", "Failed to read hex dump", true)
					ui.updateStatus("❌ Hex dump failed")
				} else {
					ui.displayOutput("Hex Dump", output, false)
					ui.updateStatus("✓ Hex dump loaded")
				}
			}()
		}, ui.window)
}

func (ui *AnalyzerUI) onEditHex() {
	path := ui.getFilePath()
	if path == "" {
		return
	}

	offsetInput := widget.NewEntry()
	offsetInput.SetPlaceHolder("Offset (hex or decimal)")
	offsetInput.Text = "0"

	items := container.NewVBox(
		widget.NewLabel("Open hex editor at offset:"),
		widget.NewLabel("Offset:"),
		offsetInput,
	)

	dialog.ShowCustomConfirm("Open Hex Editor", "Open", "Cancel",
		container.NewVBox(items),
		func(ok bool) {
			if !ok {
				return
			}

			var offset int64
			if _, err := fmt.Sscanf(offsetInput.Text, "%x", &offset); err != nil {
				if _, err := fmt.Sscanf(offsetInput.Text, "%d", &offset); err != nil {
					ui.displayOutput("", "Invalid offset: "+err.Error(), true)
					ui.updateStatus("❌ Invalid offset")
					return
				}
			}

			editor := &HexEditor{
				filePath:  path,
				startAddr: offset,
				offset:    offset,
				mainApp:   ui.app,
			}
			editor.OpenWindow()
		}, ui.window)
}

func (he *HexEditor) OpenWindow() {
	he.mainApp.Settings().SetTheme(CustomTheme{})
	window := he.mainApp.NewWindow("Hex Editor - " + he.filePath)
	window.Resize(fyne.NewSize(1200, 800))

	// Верхняя панель с навигацией
	jumpOffsetInput := widget.NewEntry()
	jumpOffsetInput.SetPlaceHolder("Jump to offset (hex or decimal)")
	jumpOffsetInput.Text = fmt.Sprintf("%x", he.offset)

	jumpBtn := widget.NewButton("Jump", func() {
		var offset int64
		if _, err := fmt.Sscanf(jumpOffsetInput.Text, "%x", &offset); err != nil {
			if _, err := fmt.Sscanf(jumpOffsetInput.Text, "%d", &offset); err != nil {
				fyne.Do(func() {
					dialog.ShowError(err, window)
				})
				return
			}
		}
		he.offset = offset
		he.loadDataAndRefresh()
	})

	he.offsetLabel = widget.NewLabel(fmt.Sprintf("Offset: 0x%x (%d)", he.offset, he.offset))

	topBar := container.NewHBox(
		widget.NewLabel("Go to offset:"),
		jumpOffsetInput,
		jumpBtn,
		he.offsetLabel,
	)

	// Container для редактируемого hex view
	he.hexEntries = make([]*widget.Entry, 256) // Макс 256 байт на экран
	he.hexContainer = container.NewVBox()

	hexScroll := container.NewScroll(he.hexContainer)
	hexScroll.SetMinSize(fyne.NewSize(1180, 400))

	// Buttons для навигации
	prevBtn := widget.NewButton("◀ Previous 16 lines", func() {
		if he.offset >= 256 {
			he.offset -= 256
			he.loadDataAndRefresh()
		}
	})

	nextBtn := widget.NewButton("Next 16 lines ▶", func() {
		he.offset += 256
		he.loadDataAndRefresh()
	})

	saveBtn := widget.NewButton("💾 Save Changes", func() {
		if !he.modified {
			fyne.Do(func() {
				dialog.ShowInformation("Info", "No changes to save", window)
			})
			return
		}

		fyne.Do(func() {
			dialog.ShowConfirm("Save", "Save changes to file?", func(ok bool) {
				if !ok {
					return
				}

				if err := he.saveChanges(); err != nil {
					dialog.ShowError(err, window)
				} else {
					dialog.ShowInformation("Success", "Changes saved successfully", window)
					he.modified = false
					he.loadDataAndRefresh()
				}
			}, window)
		})
	})

	navButtons := container.NewHBox(
		prevBtn,
		nextBtn,
		saveBtn,
	)

	// Layout
	content := container.NewVBox(
		topBar,
		widget.NewLabel("Hex Editor (edit values directly):"),
		hexScroll,
		navButtons,
	)

	window.SetContent(content)
	window.Show()

	// Загружаем данные
	he.loadDataAndRefresh()
}

func (he *HexEditor) loadData() error {
	f, err := os.Open(he.filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	fileSize := fi.Size()
	if he.offset >= fileSize {
		return fmt.Errorf("offset is beyond file size")
	}

	if _, err := f.Seek(he.offset, 0); err != nil {
		return err
	}

	// Читаем достаточно данных для отображения (16 строк по 16 байт)
	readSize := int64(256)
	if he.offset+readSize > fileSize {
		readSize = fileSize - he.offset
	}

	he.data = make([]byte, readSize)
	n, err := f.Read(he.data)
	if err != nil && err != io.EOF {
		return err
	}
	he.data = he.data[:n]

	return nil
}

func (he *HexEditor) loadDataAndRefresh() {
	go func() {
		if err := he.loadData(); err != nil {
			fyne.Do(func() {
				// Обработка ошибки
			})
			return
		}
		he.refreshDisplay()
	}()
}

func (he *HexEditor) refreshDisplay() {
	// Создаем интерактивные поля для редактирования
	fyne.Do(func() {
		he.hexContainer.RemoveAll()
		he.hexEntries = make([]*widget.Entry, len(he.data))

		for i := 0; i < len(he.data); i += 16 {
			// Offset
			offsetLabel := fmt.Sprintf("%08x: ", he.offset+int64(i))

			// Hex bytes в отдельных полях
			end := i + 16
			if end > len(he.data) {
				end = len(he.data)
			}

			hexFields := container.NewHBox()

			for j := i; j < end; j++ {
				idx := j
				entry := widget.NewEntry()
				entry.SetPlaceHolder("00")
				entry.SetText(fmt.Sprintf("%02x", he.data[j]))
				entry.OnChanged = func(s string) {
					he.modified = true
				}
				he.hexEntries[idx] = entry
				hexFields.Add(entry)
			}

			// ASCII representation
			ascii := ""
			for j := i; j < end; j++ {
				c := he.data[j]
				if c >= 32 && c <= 126 {
					ascii += string(c)
				} else {
					ascii += "."
				}
			}

			// Собираем строку
			rowLabel := widget.NewLabel(offsetLabel)
			asciiLabel := widget.NewLabel("| " + ascii)

			row := container.NewHBox(
				rowLabel,
				hexFields,
				asciiLabel,
			)

			he.hexContainer.Add(row)
		}

		// Обновляем label
		he.offsetLabel.SetText(fmt.Sprintf("Offset: 0x%x (%d) | Size: %d bytes", he.offset, he.offset, len(he.data)))
	})
}

func (he *HexEditor) saveChanges() error {
	// Собираем все измененные данные из Entry fields
	var data []byte
	for i := 0; i < len(he.hexEntries); i++ {
		if he.hexEntries[i] == nil {
			continue
		}
		text := he.hexEntries[i].Text
		if text == "" {
			text = "00"
		}
		var b byte
		if _, err := fmt.Sscanf(text, "%x", &b); err != nil {
			return fmt.Errorf("invalid hex at position %d: %v", i, err)
		}
		data = append(data, b)
	}

	// Пишем в файл
	return writeHexData(he.filePath, he.offset, data)
}

func (he *HexEditor) save() error {
	if !he.modified {
		return nil
	}

	// Собираем измененные данные
	var data []byte
	for i := 0; i < 16; i++ {
		text := he.hexEntries[i].Text
		if text == "" {
			text = "00"
		}
		var b byte
		if _, err := fmt.Sscanf(text, "%x", &b); err != nil {
			return fmt.Errorf("invalid hex at position %d: %v", i, err)
		}
		data = append(data, b)
	}

	// Пишем в файл
	return writeHexData(he.filePath, he.offset, data)
}

func (ui *AnalyzerUI) updateStatus(msg string) {
	fyne.Do(func() {
		ui.statusBar.SetText(msg)
	})
}

func RunGUI() {
	ui := NewAnalyzerUI()
	ui.Run()
}
