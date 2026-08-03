package handlers

import (
	"black-hat/models"
	"black-hat/services"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

var (
	analyses    = make(map[int]*models.AnalysisResult)
	analysesMu  sync.RWMutex
	analysisID  = 0
)

type HomeHandler struct{}

func (h *HomeHandler) Home(c *fiber.Ctx) error {
	return RenderTemplate(c, "home", nil)
}

type UploadHandler struct{}

func (u *UploadHandler) UploadPage(c *fiber.Ctx) error {
	return RenderTemplate(c, "upload", nil)
}

func (u *UploadHandler) Upload(c *fiber.Ctx) error {
	file, err := c.FormFile("project")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "No file uploaded"})
	}

	if !strings.HasSuffix(strings.ToLower(file.Filename), ".zip") {
		return c.Status(400).JSON(fiber.Map{"error": "Unsupported archive. Please upload a ZIP file."})
	}

	if file.Size > 52428800 {
		return c.Status(400).JSON(fiber.Map{"error": "File too large. Maximum size is 50MB."})
	}

	uploadDir := "./uploads"
	os.MkdirAll(uploadDir, 0755)

	savePath := filepath.Join(uploadDir, fmt.Sprintf("%d_%s", time.Now().UnixNano(), file.Filename))
	if err := c.SaveFile(file, savePath); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save file"})
	}

	extractor := services.NewExtractor()
	extractDir := filepath.Join(uploadDir, fmt.Sprintf("project_%d", time.Now().UnixNano()))
	os.MkdirAll(extractDir, 0755)

	if err := extractor.ExtractZIP(savePath, extractDir); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to extract archive"})
	}

	analysisID++
	projectID := analysisID

	lang, _ := c.Locals("lang").(string)
	if lang == "" {
		lang = "en"
	}

	go runAnalysis(projectID, extractDir)

	return c.JSON(fiber.Map{
		"success":     true,
		"analysis_id": projectID,
		"message":     "Analysis started",
	})
}

func runAnalysis(projectID int, projectPath string) {
	analyzer := services.NewAnalyzer()
	start := time.Now()
	result, err := analyzer.AnalyzeProject(projectPath)
	duration := time.Since(start)

	if err != nil {
		analysesMu.Lock()
		analyses[projectID] = &models.AnalysisResult{
			FilesScanned:    0,
			DurationSeconds: int(duration.Seconds()),
		}
		analysesMu.Unlock()
		return
	}

	result.DurationSeconds = int(duration.Seconds())
	analysesMu.Lock()
	analyses[projectID] = result
	analysesMu.Unlock()
}

type AnalysisHandler struct{}

func (a *AnalysisHandler) AnalysisPage(c *fiber.Ctx) error {
	id := c.Params("id")
	return RenderTemplate(c, "analysis", map[string]interface{}{
		"AnalysisID": id,
	})
}

type DashboardHandler struct{}

func (d *DashboardHandler) ResultsPage(c *fiber.Ctx) error {
	idStr := c.Params("id")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	analysesMu.RLock()
	result, exists := analyses[id]
	analysesMu.RUnlock()

	if !exists {
		return RenderTemplate(c, "results", map[string]interface{}{
			"HasResult": false,
			"AnalysisID": idStr,
		})
	}

	return RenderTemplate(c, "results", map[string]interface{}{
		"HasResult":  true,
		"AnalysisID": idStr,
		"Result":     result,
	})
}

type ReportsHandler struct{}

func (r *ReportsHandler) ReportsPage(c *fiber.Ctx) error {
	idStr := c.Params("id")
	return RenderTemplate(c, "report", map[string]interface{}{
		"AnalysisID": idStr,
	})
}

func (r *ReportsHandler) DownloadReport(c *fiber.Ctx) error {
	idStr := c.Params("id")
	format := c.Params("format")

	var id int
	fmt.Sscanf(idStr, "%d", &id)

	analysesMu.RLock()
	result, exists := analyses[id]
	analysesMu.RUnlock()

	if !exists {
		return c.Status(404).JSON(fiber.Map{"error": "Analysis not found"})
	}

	reporter := services.NewReporter()
	lang, _ := c.Locals("lang").(string)
	if lang == "" {
		lang = "en"
	}

	switch format {
	case "json":
		data, err := reporter.GenerateJSON(result)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to generate report"})
		}
		c.Set("Content-Type", "application/json")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"blackhat-report-%d.json\"", id))
		return c.Send(data)
	case "html":
		html := reporter.GenerateHTML(result, lang)
		c.Set("Content-Type", "text/html")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"blackhat-report-%d.html\"", id))
		return c.SendString(html)
	default:
		return c.Status(400).JSON(fiber.Map{"error": "Unsupported format"})
	}
}

type APIHandler struct{}

func (api *APIHandler) AnalysisStatus(c *fiber.Ctx) error {
	idStr := c.Params("id")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	analysesMu.RLock()
	result, exists := analyses[id]
	analysesMu.RUnlock()

	if !exists {
		return c.JSON(fiber.Map{
			"status": "running",
		})
	}

	return c.JSON(fiber.Map{
		"status":        "completed",
		"files_scanned": result.FilesScanned,
		"duration":      result.DurationSeconds,
	})
}

func (api *APIHandler) SecurityResults(c *fiber.Ctx) error {
	idStr := c.Params("id")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	analysesMu.RLock()
	result, exists := analyses[id]
	analysesMu.RUnlock()

	if !exists {
		return c.JSON(fiber.Map{"findings": []interface{}{}})
	}

	return c.JSON(fiber.Map{"findings": result.SecurityFindings})
}

func (api *APIHandler) QualityResults(c *fiber.Ctx) error {
	idStr := c.Params("id")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	analysesMu.RLock()
	result, exists := analyses[id]
	analysesMu.RUnlock()

	if !exists {
		return c.JSON(fiber.Map{"findings": []interface{}{}, "metrics": models.QualityMetrics{}})
	}

	return c.JSON(fiber.Map{
		"findings": result.QualityFindings,
		"metrics":  result.QualityMetrics,
	})
}

func (api *APIHandler) DependencyResults(c *fiber.Ctx) error {
	idStr := c.Params("id")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	analysesMu.RLock()
	result, exists := analyses[id]
	analysesMu.RUnlock()

	if !exists {
		return c.JSON(fiber.Map{"vulnerabilities": []interface{}{}})
	}

	return c.JSON(fiber.Map{"vulnerabilities": result.DependencyVulns})
}
