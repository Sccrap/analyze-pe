package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"strings"
)

const webPort = "8080"

type WebServer struct {
	server *http.Server
}

type AnalysisRequest struct {
	FilePath string `json:"filePath"`
	Type     string `json:"type"`
}

type AnalysisResponse struct {
	Success bool   `json:"success"`
	Data    string `json:"data"`
	Error   string `json:"error,omitempty"`
}

var webAssets = map[string]string{
	"index.html": `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PE Analyzer - Web Interface</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d4a 100%);
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        header {
            background: rgba(41, 45, 62, 0.9);
            border-bottom: 2px solid #64b5f6;
            padding: 2rem;
            text-align: center;
        }

        header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            color: #64b5f6;
        }

        header p {
            color: #90caf9;
            font-size: 0.95rem;
        }

        .container {
            flex: 1;
            max-width: 1200px;
            margin: 2rem auto;
            width: 100%;
            padding: 0 2rem;
        }

        .card {
            background: rgba(37, 37, 53, 0.8);
            border: 1px solid #64b5f6;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }

        .card h2 {
            color: #64b5f6;
            margin-bottom: 1.5rem;
            font-size: 1.3rem;
            border-bottom: 1px solid #64b5f6;
            padding-bottom: 0.5rem;
        }

        .file-input-group {
            margin-bottom: 1.5rem;
        }

        input[type="file"] {
            display: block;
            margin-bottom: 1rem;
            padding: 0.5rem;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid #64b5f6;
            border-radius: 4px;
            color: #e0e0e0;
            cursor: pointer;
        }

        input[type="file"]::file-selector-button {
            background: #64b5f6;
            color: #1e1e2e;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }

        input[type="file"]::file-selector-button:hover {
            background: #42a5f5;
        }

        .file-info {
            background: rgba(0, 0, 0, 0.2);
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            display: none;
        }

        .file-info.active {
            display: block;
        }

        .file-info p {
            margin: 0.5rem 0;
            color: #90caf9;
        }

        .buttons-group {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        button {
            padding: 0.75rem 1.5rem;
            background: #64b5f6;
            color: #1e1e2e;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            transition: background 0.3s;
        }

        button:hover {
            background: #42a5f5;
        }

        button:disabled {
            background: #424242;
            cursor: not-allowed;
            color: #757575;
        }

        .output-container {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid #424242;
            border-radius: 4px;
            padding: 1rem;
            margin-top: 1rem;
            max-height: 500px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.5;
            display: none;
        }

        .output-container.active {
            display: block;
        }

        .output-container pre {
            margin: 0;
            color: #90caf9;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .error {
            color: #ef5350;
        }

        .loading {
            display: none;
            text-align: center;
            margin: 1rem 0;
        }

        .loading.active {
            display: block;
        }

        .spinner {
            border: 3px solid #424242;
            border-top: 3px solid #64b5f6;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        footer {
            text-align: center;
            padding: 2rem;
            color: #757575;
            border-top: 1px solid #424242;
            margin-top: auto;
        }

        .status-bar {
            background: rgba(41, 45, 62, 0.9);
            padding: 1rem 2rem;
            border-top: 1px solid #424242;
            color: #90caf9;
        }

        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.2);
        }

        ::-webkit-scrollbar-thumb {
            background: #64b5f6;
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #42a5f5;
        }
    </style>
</head>
<body>
    <header>
        <h1>🔍 PE Analyzer</h1>
        <p>Advanced Portable Executable Analysis Tool</p>
    </header>

    <div class="container">
        <div class="card">
            <h2>1. Select File</h2>
            <div class="file-input-group">
                <input type="file" id="fileInput" accept=".exe,.dll" required>
                <div class="file-info" id="fileInfo">
                    <p><strong>File:</strong> <span id="fileName"></span></p>
                    <p><strong>Size:</strong> <span id="fileSize"></span> bytes</p>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>2. Analysis Tools</h2>
            <div class="buttons-group">
                <button onclick="runAnalysis('basic')">📊 Basic Info</button>
                <button onclick="runAnalysis('imports')">📦 Imports</button>
                <button onclick="runAnalysis('sections')">🔧 Sections</button>
                <button onclick="runAnalysis('debug')">🐛 Debug Info</button>
                <button onclick="runAnalysis('strings')">📄 Strings</button>
            </div>
        </div>

        <div class="card">
            <h2>3. Results</h2>
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Analyzing...</p>
            </div>
            <div class="output-container" id="output">
                <pre id="outputText"></pre>
            </div>
        </div>
    </div>

    <div class="status-bar">
        <span id="status">✓ Ready to analyze</span>
    </div>

    <footer>
        <p>PE Analyzer Web Interface | Secure PE File Analysis</p>
    </footer>

    <script>
        let selectedFile = null;

        document.getElementById('fileInput').addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                selectedFile = file;
                document.getElementById('fileName').textContent = file.name;
                document.getElementById('fileSize').textContent = file.size;
                document.getElementById('fileInfo').classList.add('active');
                updateStatus('✓ File selected: ' + file.name);
            }
        });

        function updateStatus(msg) {
            document.getElementById('status').textContent = msg;
        }

        function showOutput(data) {
            document.getElementById('outputText').textContent = data;
            document.getElementById('output').classList.add('active');
        }

        function showError(error) {
            const errorMsg = '❌ Error\n' + error;
            document.getElementById('outputText').innerHTML = '<span class="error">' + errorMsg + '</span>';
            document.getElementById('output').classList.add('active');
        }

        async function runAnalysis(type) {
            if (!selectedFile) {
                alert('Please select a file first');
                return;
            }

            const formData = new FormData();
            formData.append('file', selectedFile);
            formData.append('type', type);

            updateStatus('🔄 Analyzing ' + type + '...');
            document.getElementById('loading').classList.add('active');

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    showOutput(result.data);
                    updateStatus('✓ Analysis complete');
                } else {
                    showError(result.error);
                    updateStatus('❌ Analysis failed');
                }
            } catch (error) {
                showError(error.message);
                updateStatus('❌ Request failed');
            } finally {
                document.getElementById('loading').classList.remove('active');
            }
        }
    </script>
</body>
</html>`,
}

func NewWebServer() *WebServer {
	mux := http.NewServeMux()

	// Serve static files
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/analyze", handleAnalyze)

	server := &http.Server{
		Addr:    ":" + webPort,
		Handler: mux,
	}

	return &WebServer{server: server}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(webAssets["index.html"]))
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(AnalysisResponse{
			Success: false,
			Error:   "Only POST requests allowed",
		})
		return
	}

	// Parse multipart form
	r.ParseMultipartForm(100 << 20) // 100MB max

	file, _, err := r.FormFile("file")
	if err != nil {
		json.NewEncoder(w).Encode(AnalysisResponse{
			Success: false,
			Error:   "Failed to read file: " + err.Error(),
		})
		return
	}
	defer file.Close()

	analysisType := r.FormValue("type")

	// Write temp file
	tmpFile, err := os.CreateTemp("", "pe_*.exe")
	if err != nil {
		json.NewEncoder(w).Encode(AnalysisResponse{
			Success: false,
			Error:   "Failed to create temp file: " + err.Error(),
		})
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, file); err != nil {
		json.NewEncoder(w).Encode(AnalysisResponse{
			Success: false,
			Error:   "Failed to save file: " + err.Error(),
		})
		return
	}
	tmpFile.Close()

	// Run analysis with optimized output
	var output strings.Builder

	switch analysisType {
	case "basic":
		oldStdout := os.Stdout
		pipeR, pipeW, _ := os.Pipe()
		os.Stdout = pipeW
		basicInfo(tmpFile.Name())
		pipeW.Close()
		io.Copy(&output, pipeR)
		os.Stdout = oldStdout

	case "imports":
		oldStdout := os.Stdout
		pipeR, pipeW, _ := os.Pipe()
		os.Stdout = pipeW
		importsPE(tmpFile.Name())
		pipeW.Close()
		io.Copy(&output, pipeR)
		os.Stdout = oldStdout

	case "sections":
		oldStdout := os.Stdout
		pipeR, pipeW, _ := os.Pipe()
		os.Stdout = pipeW
		sectionsPE(tmpFile.Name())
		pipeW.Close()
		io.Copy(&output, pipeR)
		os.Stdout = oldStdout

	case "debug":
		oldStdout := os.Stdout
		pipeR, pipeW, _ := os.Pipe()
		os.Stdout = pipeW
		debugInfo(tmpFile.Name())
		pipeW.Close()
		io.Copy(&output, pipeR)
		os.Stdout = oldStdout

	case "strings":
		// Optimized: directly get strings without stdout redirection
		fileData, err := os.ReadFile(tmpFile.Name())
		if err == nil {
			strings := extractStringsData(fileData, 4)
			// Limit to 10000 strings to avoid slowdown
			if len(strings) > 10000 {
				strings = strings[:10000]
				output.WriteString(fmt.Sprintf("(Showing first 10000 of %d strings)\n\n", len(strings)))
			}
			for _, s := range strings {
				output.WriteString(s + "\n")
			}
		} else {
			json.NewEncoder(w).Encode(AnalysisResponse{
				Success: false,
				Error:   "Failed to read file: " + err.Error(),
			})
			return
		}

	default:
		json.NewEncoder(w).Encode(AnalysisResponse{
			Success: false,
			Error:   "Unknown analysis type: " + analysisType,
		})
		return
	}

	result := AnalysisResponse{
		Success: true,
		Data:    html.EscapeString(output.String()),
	}

	json.NewEncoder(w).Encode(result)
}

func (ws *WebServer) Start() error {
	fmt.Printf("🌐 Web server starting at http://localhost:%s\n", webPort)
	return ws.server.ListenAndServe()
}

func (ws *WebServer) Close() error {
	return ws.server.Close()
}

func RunWebUI() error {
	ws := NewWebServer()
	return ws.Start()
}
