package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"black-hat/i18n"
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

	// orderSlots is the order/queue system: the site handles up to 100 orders
	// (uploads) at once. Each upload must reserve a slot before its analysis
	// starts; when all 100 slots are busy, the 101st upload is told to wait
	// until the current scans finish. As soon as one finishes, its slot is
	// freed and the next upload (order 101) takes its place. The capacity is
	// configurable via MAX_CONCURRENT_ANALYSES.
	orderSlots = make(chan struct{}, maxConcurrentOrders())
)

// maxConcurrentOrders returns how many analyses may run at the same time
// (the order limit). Defaults to 100; override with MAX_CONCURRENT_ANALYSES.
func maxConcurrentOrders() int {
	n := 100
	if v := os.Getenv("MAX_CONCURRENT_ANALYSES"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	return n
}

// reserveOrderSlot tries to take one of the order slots. It returns true when
// a slot was reserved (the upload may proceed) and false when the queue is
// full (the next concurrent upload must wait).
func reserveOrderSlot() bool {
	select {
	case orderSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseOrderSlot frees an order slot after an analysis finishes, letting
// the next waiting upload (order 101) take the place of the finished one.
func releaseOrderSlot() {
	<-orderSlots
}

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

	lang := middleware.LangFrom(r)
	translate := func(key string) string { return i18n.GetInstance().Translate(lang, key) }

	// Give the body an effectively-unlimited ceiling; only the 5 GB safety net
	// guards the serverless worker from an absurd single request.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadMem); err != nil {
		// Tell the client apart: "the request is simply too big" gets its own
		// 413 and message instead of a generic upload error.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			middleware.WriteJSON(w, http.StatusRequestEntityTooLarge, map[string]interface{}{
				"error":     translate("errors.uploadTooLarge"),
				"too_large": true,
				"max_bytes": maxErr.Limit,
			})
			return
		}
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": translate("errors.uploadFailed")})
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
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": translate("errors.noFileUploaded")})
		return
	}
	defer file.Close()

	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": translate("errors.unsupportedArchive")})
		return
	}

	// ---- Order queue: up to 100 analyses run at once ----
	// If all slots are taken, the next upload is told to wait until one of the
	// running scans finishes; the finished scan's slot then goes to the next
	// upload. The check happens here — before any file is saved or extracted,
	// so a rejected order costs nothing (no temp files, no wasted extraction).
	if !reserveOrderSlot() {
		writeQueueFull(w, r)
		return
	}
	defer releaseOrderSlot()

	// ---- All file I/O happens under /tmp (os.TempDir) ----
	tmpRoot := os.TempDir()
	uploadDir := filepath.Join(tmpRoot, "blackhat-uploads")
	os.MkdirAll(uploadDir, 0o755)

	savePath := filepath.Join(uploadDir, fmt.Sprintf("%d_%s", time.Now().UnixNano(), sanitizeFilename(header.Filename)))

	out, err := os.Create(savePath)
	if err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": translate("errors.failedToSave")})
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		os.Remove(savePath)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": translate("errors.failedToSave")})
		return
	}
	out.Close()

	u.analyzeArchive(w, savePath, lang)
}

// analyzeArchive is the shared tail of both upload paths (direct multipart and
// direct-to-Blob): it extracts the ZIP at zipPath into a fresh workspace under
// /tmp, runs the analysis synchronously (bounded by ANALYSIS_TIMEOUT so a big
// project can never blow a serverless request window), cleans up and answers
// with the analysis id. The order slot is already reserved by the caller.
func (u *UploadHandler) analyzeArchive(w http.ResponseWriter, zipPath string, lang string) {
	translate := func(key string) string { return i18n.GetInstance().Translate(lang, key) }
	tmpRoot := os.TempDir()
	extractDir := filepath.Join(tmpRoot, "blackhat-projects")
	os.MkdirAll(extractDir, 0o755)

	projectDir := filepath.Join(extractDir, fmt.Sprintf("project_%d", time.Now().UnixNano()))
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		os.Remove(zipPath)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": translate("errors.failedToPrepareWorkspace")})
		return
	}

	extractor := services.NewExtractor()
	if err := extractor.ExtractZIP(zipPath, projectDir); err != nil {
		os.Remove(zipPath)
		os.RemoveAll(projectDir)
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": translate("errors.failedToExtract")})
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
	runAnalysis(projectID, projectDir, zipPath)

	middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"analysis_id": projectID,
		"status":      "completed",
		"message":     "Analysis complete",
	})
}

// writeQueueFull answers a 429 when every analysis slot is busy.
func writeQueueFull(w http.ResponseWriter, r *http.Request) {
	lang := middleware.LangFrom(r)
	max := maxConcurrentOrders()
	msg := fmt.Sprintf(i18n.GetInstance().Translate(lang, "errors.queueFull"), max)
	w.Header().Set("Retry-After", "60")
	middleware.WriteJSON(w, http.StatusTooManyRequests, map[string]interface{}{
		"error":               msg,
		"queue_full":          true,
		"max_orders":          max,
		"retry_after_seconds": 60,
	})
}

// UploadToken mints a client upload token for the direct-to-Blob upload path
// (the browser PUTs the ZIP straight to Vercel Blob, bypassing the 4.5 MB
// platform body limit that makes large direct uploads fail). The request is
// tiny JSON, so it always fits the platform limit. When no Blob store is
// configured it answers {"enabled":false} and the client falls back to the
// classic direct multipart upload.
func (u *UploadHandler) UploadToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		middleware.WriteJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "Method not allowed"})
		return
	}

	store := services.NewBlobStore()
	if !store.Enabled() {
		middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{"enabled": false})
		return
	}

	var req struct {
		Filename string `json:"filename"`
	}
	if r.Body != nil {
		json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req)
	}
	filename := "project.zip"
	if req.Filename != "" {
		filename = sanitizeFilename(req.Filename)
	}
	if !strings.HasSuffix(strings.ToLower(filename), ".zip") {
		filename += ".zip"
	}
	pathname := fmt.Sprintf("uploads/%d_%s", time.Now().UnixNano(), filename)

	token, expires, err := store.ClientToken(pathname)
	if err != nil {
		lang := middleware.LangFrom(r)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": i18n.GetInstance().Translate(lang, "errors.uploadFailed")})
		return
	}
	uploadURL, blobURL := store.UploadURL(pathname)

	middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":     true,
		"token":       token,
		"store_id":    store.StoreID(),
		"access":      store.Access(),
		"upload_url":  uploadURL,
		"blob_url":    blobURL,
		"api_version": store.APIVersion(),
		"expires_at":  expires.Unix(),
	})
}

// CompleteUpload finalizes a direct-to-Blob upload. The browser has already
// PUT the ZIP to Vercel Blob (no platform body limit), so this endpoint
// downloads it server-side — also exempt from the client body limit — extracts
// it and runs the exact same analysis pipeline as a direct upload.
func (u *UploadHandler) CompleteUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		middleware.WriteJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "Method not allowed"})
		return
	}

	lang := middleware.LangFrom(r)
	translate := func(key string) string { return i18n.GetInstance().Translate(lang, key) }

	var req struct {
		BlobURL string `json:"blobUrl"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.BlobURL == "" {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": translate("errors.uploadFailed")})
		return
	}
	if !strings.HasPrefix(req.BlobURL, "https://") {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": translate("errors.uploadFailed")})
		return
	}

	store := services.NewBlobStore()
	if !store.Enabled() {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": translate("errors.largeUploadNotConfigured")})
		return
	}

	if !reserveOrderSlot() {
		writeQueueFull(w, r)
		return
	}
	defer releaseOrderSlot()

	tmpRoot := os.TempDir()
	uploadDir := filepath.Join(tmpRoot, "blackhat-uploads")
	os.MkdirAll(uploadDir, 0o755)
	savePath := filepath.Join(uploadDir, fmt.Sprintf("%d_project.zip", time.Now().UnixNano()))

	if _, err := store.DownloadTo(req.BlobURL, savePath); err != nil {
		os.Remove(savePath)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": translate("errors.uploadFailed")})
		return
	}
	// The object is on disk now — free the store space immediately
	// (best-effort; a failed delete is only a storage-leak risk, not a bug).
	_ = store.Delete(req.BlobURL)

	u.analyzeArchive(w, savePath, lang)
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

	// A large project can take a while, but the whole analysis must still fit
	// inside the platform's function window (300 s on Vercel Hobby). The
	// watchdog caps the pipeline at ANALYSIS_TIMEOUT (default 600 s) so a big
	// upload degrades into a clear timeout result instead of a request cut off
	// mid-flight by the platform. When the deadline fires, the abandoned
	// AnalyzeProject goroutine keeps running in the background but stays
	// bounded: every tool subprocess has its own per-tool timeout and the
	// cleanup below removes the project dir, so it fails fast and drains.
	analyzer := services.NewAnalyzer()
	start := time.Now()

	type outcome struct {
		result *models.AnalysisResult
		err    error
	}
	ch := make(chan outcome, 1)
	go func() {
		result, err := analyzer.AnalyzeProject(projectDir)
		ch <- outcome{result: result, err: err}
	}()

	deadline := analysisDeadline()
	var o outcome
	select {
	case o = <-ch:
	case <-time.After(deadline):
		o = outcome{err: fmt.Errorf("analysis exceeded the %s deadline", deadline)}
	}
	duration := time.Since(start)

	if o.err != nil {
		analysesMu.Lock()
		analyses[projectID] = &models.AnalysisResult{
			FilesScanned:    0,
			DurationSeconds: int(duration.Seconds()),
			Error:           o.err.Error(),
		}
		analysesMu.Unlock()
		return
	}

	o.result.DurationSeconds = int(duration.Seconds())
	analysesMu.Lock()
	analyses[projectID] = o.result
	analysesMu.Unlock()
}

// analysisDeadline is the hard cap for a single analysis run, from the
// ANALYSIS_TIMEOUT env var (seconds; default 600). Deployments with a tighter
// platform window (Vercel Hobby: 300 s) should set it a little below that.
func analysisDeadline() time.Duration {
	if v := os.Getenv("ANALYSIS_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 600 * time.Second
}

// RunFolderAnalysis scans a local directory in place — the desktop-app path.
// Unlike the upload flow there is nothing to extract and, critically, nothing
// to delete afterwards: the user's project stays untouched on disk. The
// analysis runs in a background goroutine (a desktop process has no
// serverless request window to honor) and the result lands in the same
// in-memory store, so the existing /analysis/:id poller and /results/:id page
// work unchanged. The caller receives the analysis id immediately.
func RunFolderAnalysis(projectPath string) (int, error) {
	info, err := os.Stat(projectPath)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("path is not a directory: %s", projectPath)
	}

	projectID := int(analysisID.Add(1))
	analysesMu.Lock()
	pending[projectID] = struct{}{}
	analysesMu.Unlock()

	go func() {
		defer func() {
			analysesMu.Lock()
			delete(pending, projectID)
			analysesMu.Unlock()
		}()

		analyzer := services.NewAnalyzer()
		start := time.Now()
		result, err := analyzer.AnalyzeProject(projectPath)
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
	}()

	return projectID, nil
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
