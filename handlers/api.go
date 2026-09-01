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

	// Register the analysis as in-flight *before* answering, on this instance
	// (pending) and in shared storage (running state), so a status poll that
	// lands on ANY container instance sees "running" immediately instead of
	// "analysis not found".
	analysesMu.Lock()
	pending[projectID] = struct{}{}
	analysesMu.Unlock()
	store := services.ResultStoreInstance()
	store.MarkRunning(projectID)

	// Run the analysis in the background and answer right away. The response
	// no longer stays open for the whole scan (which the platform used to cut
	// off on long projects), and the report is written to shared Blob storage
	// as soon as it is ready, so whichever instance the browser hits next can
	// serve /analysis/:id, /results/:id and the report APIs. The client polls
	// the status endpoint and is forwarded to the results page on completion.
	//
	// A synchronous mode stays available via ANALYSIS_SYNC=1 for hosts where
	// background goroutines cannot outlive a request (plain serverless
	// functions), preserving the original behaviour there.
	if os.Getenv("ANALYSIS_SYNC") == "1" {
		runAnalysis(projectID, projectDir, zipPath)
		middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
			"success":     true,
			"analysis_id": projectID,
			"status":      "completed",
			"message":     "Analysis complete",
		})
		return
	}

	go runAnalysis(projectID, projectDir, zipPath)
	middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"analysis_id": projectID,
		"status":      "running",
		"message":     "Analysis accepted",
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

// runAnalysis executes the SAST pipeline, persists the result (memory + shared
// Blob storage when enabled) and cleans up every temporary file (uploaded ZIP
// + extracted tree) so /tmp never fills up on Vercel's ephemeral disk. It runs
// in a background goroutine on container hosts: the deployment keeps the
// container warm while the browser polls the status endpoint, so the report
// always lands — even for scans that outlive the old synchronous request.
//
// Whatever happens, a report is stored: a real one on success, or an
// Error-marked result on failure/timeout. Clients therefore always reach a
// readable outcome, never a void "no results" page. The order slot is released
// here too, so the queue only counts analyses that are actually running.
//
// ANALYSIS_SYNC=1 flips the caller into synchronous mode; in that mode this
// function is still safe to call before the response is written.
func runAnalysis(projectID int, projectDir, zipPath string) {
	store := services.ResultStoreInstance()

	// Heartbeat the "running" marker so a shared-storage reader can never
	// mistake a long healthy scan for an orphaned one (see staleStateAfter).
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				store.MarkRunning(projectID)
			case <-stop:
				return
			}
		}
	}()

	// Register the cleanup before doing any work so it also runs on panic:
	// mark the analysis as no longer in-flight (otherwise the status
	// endpoint would report "running" forever for this id), then remove the
	// extracted project and uploaded archive and free the order slot.
	defer func() {
		close(stop)
		analysesMu.Lock()
		delete(pending, projectID)
		analysesMu.Unlock()
		os.RemoveAll(projectDir)
		os.Remove(zipPath)
		releaseOrderSlot()
	}()

	// The watchdog bounds the pipeline so a pathological scan cannot pin a
	// worker forever. On timeout the abandoned AnalyzeProject goroutine stays
	// bounded: every tool subprocess has its own per-tool timeout and the
	// cleanup above removes the project dir, so it fails fast and drains.
	// The result is a clear timeout report instead of a silently dropped scan.
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

	var result *models.AnalysisResult
	if o.err != nil {
		result = &models.AnalysisResult{
			FilesScanned:    0,
			DurationSeconds: int(duration.Seconds()),
			Error:           o.err.Error(),
		}
	} else {
		o.result.DurationSeconds = int(duration.Seconds())
		result = o.result
	}

	// Persist in memory AND shared Blob storage so any instance can render it.
	store.PutResult(projectID, result)
	store.MarkCompleted(projectID)
}

// analysisDeadline is the hard cap for a single analysis run, from the
// ANALYSIS_TIMEOUT env var (seconds; default 600). It bounds the watchdog that
// prevents a pathological scan from pinning a worker forever; on expiry a
// clear timeout report is persisted rather than the scan being dropped.
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
// analysis runs in a background goroutine (a desktop process has no serverless
// request window to honor) and the result lands in the same shared store, so
// the existing /analysis/:id poller and /results/:id page work unchanged.
// The caller receives the analysis id immediately.
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
	store := services.ResultStoreInstance()
	store.MarkRunning(projectID)

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
			result = &models.AnalysisResult{
				FilesScanned:    0,
				DurationSeconds: int(duration.Seconds()),
				Error:           err.Error(),
			}
		} else {
			result.DurationSeconds = int(duration.Seconds())
		}
		store.PutResult(projectID, result)
		store.MarkCompleted(projectID)
	}()

	return projectID, nil
}

// lookupResult retrieves an analysis result by id from the shared store
// (memory cache first, then persistent Blob storage). Store reads are safe
// across container instances, which fixes the intermittent "No analysis
// available" results page.
func lookupResult(id int) (*models.AnalysisResult, bool) {
	return services.ResultStoreInstance().FetchResult(id)
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
		// The report may still be in flight (poll landed before the background
		// analysis stored it, or on a different instance). Render the
		// "still analyzing" state instead of the misleading "No analysis
		// available" page; the template polls and reloads when it is ready.
		state := services.ResultStoreInstance().FetchState(id)
		analysesMu.RLock()
		_, running := pending[id]
		analysesMu.RUnlock()

		if state == services.StateRunning || running {
			RenderTemplate(w, r, "results", map[string]interface{}{
				"HasResult":  false,
				"Running":    true,
				"AnalysisID": idStr,
			})
			return
		}

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

		// A status poll can land on a different instance than the one running
		// the scan; the shared store carries the lifecycle state across all of
		// them, so "running" is reported correctly from anywhere.
		state := services.ResultStoreInstance().FetchState(id)

		if !running && state != services.StateRunning && state != services.StateCompleted {
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
