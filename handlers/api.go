package handlers

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"black-hat/middleware"
	"black-hat/models"
	"black-hat/services"
)

var (
	analyses   = make(map[int]*models.AnalysisResult)
	analysesMu sync.RWMutex
	// pending tracks analyses that have been accepted but not yet finished
	// (their result is still being computed in runAnalysis). It lets the
	// status endpoint tell "scan in flight" apart from "unknown analysis id"
	// instead of reporting every unknown id as "running" forever.
	pending    = make(map[int]struct{})
	analysisID atomic.Int32
)

const (
	// maxUploadMem is how much of an uploaded multipart body is kept in RAM
	// before Go spills the rest to the OS temp dir. Uploads are otherwise
	// unlimited in size.
	maxUploadMem = 32 << 20
	// maxUploadSize is a coarse safety net (5 GB) so one absurd request can't
	// exhaust the serverless worker. Every legitimate project is far below it.
	maxUploadSize = 5 << 30
)

type HomeHandler struct{}

func (h *HomeHandler) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	RenderTemplate(w, r, "home", nil)
}

type UploadHandler struct{}

func (u *UploadHandler) UploadPage(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, r, "upload", nil)
}

// Upload accepts a multipart/form-data request with a "project" ZIP file.
//
// Critical for Vercel: all file operations happen under the OS temp directory
// (os.TempDir() -> /tmp on Linux), because Vercel's Go runtime only allows
// writes there. The archive is extracted with archive/zip under strict guards:
// path-traversal rejection, per-file and total expansion caps (zip-bomb
// protection) and a maximum entry count.
func (u *UploadHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		middleware.WriteJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "Method not allowed"})
		return
	}

	// Give the body an effectively-unlimited ceiling; only the 5 GB safety net
	// guards the serverless worker from an absurd single request.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadMem); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "Upload failed"})
		return
	}
	// Remove the multipart temp files (file parts larger than the memory
	// threshold are spilled to /tmp by the stdlib) as soon as the form has
	// been parsed, so they never leak even if FormFile fails below.
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	file, header, err := r.FormFile("project")
	if err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "No file uploaded"})
		return
	}
	defer file.Close()

	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "Unsupported archive. Please upload a ZIP file."})
		return
	}

	// ---- All file I/O happens under /tmp (os.TempDir) ----
	tmpRoot := os.TempDir()
	uploadDir := filepath.Join(tmpRoot, "blackhat-uploads")
	extractDir := filepath.Join(tmpRoot, "blackhat-projects")

	os.MkdirAll(uploadDir, 0o755)
	os.MkdirAll(extractDir, 0o755)

	savePath := filepath.Join(uploadDir, fmt.Sprintf("%d_%s", time.Now().UnixNano(), sanitizeFilename(header.Filename)))

	out, err := os.Create(savePath)
	if err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Failed to save file"})
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		os.Remove(savePath)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Failed to save file"})
		return
	}
	out.Close()

	projectDir := filepath.Join(extractDir, fmt.Sprintf("project_%d", time.Now().UnixNano()))
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		os.Remove(savePath)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Failed to prepare workspace"})
		return
	}

	extractor := services.NewExtractor()
	if err := extractor.ExtractZIP(savePath, projectDir); err != nil {
		os.Remove(savePath)
		os.RemoveAll(projectDir)
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "Failed to extract archive"})
		return
	}

	projectID := int(analysisID.Add(1))

	// Run the analysis synchronously *inside* this request. On Vercel's
	// serverless Go runtime a background goroutine started after the response
	// has been sent is frozen with the idle worker, so the result would never
	// land in the in-memory store and the client would poll "running" forever
	// (the "Analyzing" dead-end). Running the scan while this request is still
	// in-flight keeps the worker alive until the report is ready and
	// guarantees results exist before the client is sent to the results page.
	runAnalysis(projectID, projectDir, savePath)

	middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"analysis_id": projectID,
		"status":      "completed",
		"message":     "Analysis complete",
	})
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_")
	return replacer.Replace(name)
}

// runAnalysis executes the SAST pipeline, stores the result and cleans up
// every temporary file (uploaded ZIP + extracted tree) so /tmp never fills up
// on Vercel's ephemeral disk. It is called synchronously from the upload
// handler — not in a background goroutine — because serverless workers freeze
// idle goroutines between requests, which would leave the analysis stuck in
// "running" forever.
func runAnalysis(projectID int, projectDir, zipPath string) {
	// Register the cleanup before doing any work so it also runs on panic:
	// mark the analysis as no longer in-flight (otherwise the status
	// endpoint would report "running" forever for this id), then remove the
	// extracted project and uploaded archive.
	defer func() {
		analysesMu.Lock()
		delete(pending, projectID)
		analysesMu.Unlock()
		os.RemoveAll(projectDir)
		os.Remove(zipPath)
	}()

	analyzer := services.NewAnalyzer()
	start := time.Now()
	result, err := analyzer.AnalyzeProject(projectDir)
	duration := time.Since(start)

	if err != nil {
		analysesMu.Lock()
		analyses[projectID] = &models.AnalysisResult{
			FilesScanned:    0,
			DurationSeconds: int(duration.Seconds()),
			Error:           err.Error(),
		}
		analysesMu.Unlock()
		return
	}

	result.DurationSeconds = int(duration.Seconds())
	analysesMu.Lock()
	analyses[projectID] = result
	analysesMu.Unlock()
}

// lookupResult retrieves an analysis result by id.
func lookupResult(id int) (*models.AnalysisResult, bool) {
	analysesMu.RLock()
	defer analysesMu.RUnlock()
	result, exists := analyses[id]
	return result, exists
}

type AnalysisHandler struct{}

func (a *AnalysisHandler) AnalysisPage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/analysis/")
	RenderTemplate(w, r, "analysis", map[string]interface{}{
		"AnalysisID": id,
	})
}

type DashboardHandler struct{}

func (d *DashboardHandler) ResultsPage(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/results/")
	id := parseInt(idStr)

	result, exists := lookupResult(id)
	if !exists {
		RenderTemplate(w, r, "results", map[string]interface{}{
			"HasResult":  false,
			"AnalysisID": idStr,
		})
		return
	}

	RenderTemplate(w, r, "results", map[string]interface{}{
		"HasResult":  true,
		"AnalysisID": idStr,
		"Result":     result,
	})
}

type ReportsHandler struct{}

func (r *ReportsHandler) ReportsPage(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, "/reports/")
	RenderTemplate(w, req, "report", map[string]interface{}{
		"AnalysisID": id,
	})
}

func (r *ReportsHandler) DownloadReport(w http.ResponseWriter, req *http.Request) {
	// Path: /api/reports/{id}/{format}
	trimmed := strings.TrimPrefix(req.URL.Path, "/api/reports/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "Invalid report path"})
		return
	}
	idStr, format := parts[0], parts[1]
	id := parseInt(idStr)

	result, exists := lookupResult(id)
	if !exists {
		middleware.WriteJSON(w, http.StatusNotFound, map[string]interface{}{"error": "Analysis not found"})
		return
	}

	reporter := services.NewReporter()
	lang := middleware.LangFrom(req)

	switch format {
	case "json":
		data, err := reporter.GenerateJSON(result)
		if err != nil {
			middleware.WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Failed to generate report"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"blackhat-report-%d.json\"", id))
		w.Write(data)
	case "html":
		html := reporter.GenerateHTML(result, lang)
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"blackhat-report-%d.html\"", id))
		w.Write([]byte(html))
	default:
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "Unsupported format"})
	}
}

type APIHandler struct{}

func (api *APIHandler) AnalysisStatus(w http.ResponseWriter, r *http.Request) {
	id := parseInt(strings.TrimPrefix(r.URL.Path, "/api/analysis/status/"))

	result, exists := lookupResult(id)
	if !exists {
		analysesMu.RLock()
		_, running := pending[id]
		analysesMu.RUnlock()

		if !running {
			// Unknown id: either it never existed (rate-limited upload, bad
			// URL) or the server restarted mid-scan. Tell the client instead
			// of reporting a fake "running" state that would poll forever.
			middleware.WriteJSON(w, http.StatusNotFound, map[string]interface{}{
				"error": "Analysis not found",
			})
			return
		}

		middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
			"status": "running",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "completed",
		"files_scanned": result.FilesScanned,
		"duration":      result.DurationSeconds,
	})
}

func (api *APIHandler) SecurityResults(w http.ResponseWriter, r *http.Request) {
	id := parseInt(strings.TrimPrefix(r.URL.Path, "/api/results/security/"))

	result, exists := lookupResult(id)
	if !exists {
		middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{"findings": []interface{}{}})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{"findings": result.SecurityFindings})
}

func (api *APIHandler) QualityResults(w http.ResponseWriter, r *http.Request) {
	id := parseInt(strings.TrimPrefix(r.URL.Path, "/api/results/quality/"))

	result, exists := lookupResult(id)
	if !exists {
		middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
			"findings": []interface{}{},
			"metrics":  models.QualityMetrics{},
		})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"findings": result.QualityFindings,
		"metrics":  result.QualityMetrics,
	})
}

func (api *APIHandler) DependencyResults(w http.ResponseWriter, r *http.Request) {
	id := parseInt(strings.TrimPrefix(r.URL.Path, "/api/results/dependencies/"))

	result, exists := lookupResult(id)
	if !exists {
		middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{"vulnerabilities": []interface{}{}})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{"vulnerabilities": result.DependencyVulns})
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
