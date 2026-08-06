package handlers

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"black-hat/i18n"

	"github.com/gofiber/fiber/v2"
)

var templates *template.Template

func init() {
	funcMap := template.FuncMap{
		"t": func(lang, key string) string {
			return i18n.GetInstance().Translate(lang, key)
		},
		"raw": func(s string) template.HTML {
			return template.HTML(s)
		},
	}

	files := getTemplateFiles("templates")
	templates = template.Must(template.New("").Funcs(funcMap).ParseFiles(files...))
}

func RenderTemplate(c *fiber.Ctx, templateName string, data map[string]interface{}) error {
	lang, ok := c.Locals("lang").(string)
	if !ok {
		lang = "en"
	}
	dir, ok := c.Locals("dir").(string)
	if !ok {
		dir = "ltr"
	}

	if data == nil {
		data = make(map[string]interface{})
	}
	data["Lang"] = lang
	data["Dir"] = dir
	data["CurrentPage"] = templateName

	return templates.ExecuteTemplate(c.Context().Response().Writer(), templateName, data)
}

func RegisterRoutes(app *fiber.App) {
	h := &HomeHandler{}
	u := &UploadHandler{}
	a := &AnalysisHandler{}
	d := &DashboardHandler{}
	r := &ReportsHandler{}
	api := &APIHandler{}

	app.Get("/", h.Home)
	app.Get("/upload", u.UploadPage)
	app.Get("/analysis/:id", a.AnalysisPage)
	app.Get("/results/:id", d.ResultsPage)
	app.Get("/reports/:id", r.ReportsPage)
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	apiGroup := app.Group("/api")
	apiGroup.Post("/upload", u.Upload)
	apiGroup.Get("/analysis/status/:id", api.AnalysisStatus)
	apiGroup.Get("/results/security/:id", api.SecurityResults)
	apiGroup.Get("/results/quality/:id", api.QualityResults)
	apiGroup.Get("/results/dependencies/:id", api.DependencyResults)
	apiGroup.Get("/reports/:id/:format", r.DownloadReport)
}

func getTemplateFiles(dir string) []string {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return files
	}
	for _, entry := range entries {
		if entry.IsDir() {
			subFiles := getTemplateFiles(filepath.Join(dir, entry.Name()))
			files = append(files, subFiles...)
		} else if strings.HasSuffix(entry.Name(), ".html") {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	return files
}
