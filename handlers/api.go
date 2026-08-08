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
	analysisID atomic.Int32
)

const maxUploadSize = 52428800 // 50 MB

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

	// Cap the request body before parsing so oversized uploads fail fast.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize+1<<20)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
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

	if header.Size > maxUploadSize {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "File too large. Maximum size is 50MB."})
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

	// The upload is valid and the scan is about to start: atomically check
	// and record the user's single daily scan quota. Failed uploads never
	// reach this point, so they don't consume the quota, and two concurrent
	// uploads from the same IP cannot both pass.
	if ok, retryAfter := rateLimiter.TryRecord(middleware.ClientIP(r)); !ok {
		os.Remove(savePath)
		os.RemoveAll(projectDir)
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
		middleware.WriteJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":               "Rate limit exceeded: you can scan only one project per day. Please try again tomorrow.",
			"retry_after_seconds": retryAfter,
		})
		return
	}

	projectID := int(analysisID.Add(1))

	go runAnalysis(projectID, projectDir, savePath)

	middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"analysis_id": projectID,
		"message":     "Analysis started",
	})
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_")
	return replacer.Replace(name)
}

// runAnalysis executes the SAST pipeline in a background goroutine, stores the
// result and cleans up every temporary file (uploaded ZIP + extracted tree) so
// /tmp never fills up on Vercel's ephemeral disk.
func runAnalysis(projectID int, projectDir, zipPath string) {
	analyzer := services.NewAnalyzer()
	start := time.Now()
	result, err := analyzer.AnalyzeProject(projectDir)
	duration := time.Since(start)

	// Always clean up: extracted project and uploaded archive.
	defer func() {
		os.RemoveAll(projectDir)
		os.Remove(zipPath)
	}()

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
