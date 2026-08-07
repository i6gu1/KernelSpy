package handlers

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"black-hat/i18n"
	"black-hat/middleware"

	"github.com/gofiber/fiber/v2"
)

var rateLimiter = middleware.NewScanRateLimiter()

// templates holds one compiled template set per page. Every page file
// defines its own {{"content"}} block, so pages must NOT be parsed into a
// single shared set: Go's html/template lets the last-parsed definition of
// a name win, which would make every route render the last page parsed.
// Building a separate set per page (shared layout + partials + that page)
// guarantees each page renders its own content.
var templates = map[string]*template.Template{}

func init() {
	funcMap := template.FuncMap{
		"t": func(lang, key string) string {
			return i18n.GetInstance().Translate(lang, key)
		},
		"raw": func(s string) template.HTML {
			return template.HTML(s)
		},
	}

	var shared []string
	shared = append(shared, getTemplateFiles("templates/layouts")...)
	shared = append(shared, getTemplateFiles("templates/components")...)
	shared = append(shared, getTemplateFiles("templates/partials")...)

	for _, page := range getTemplateFiles("templates/pages") {
		name := strings.TrimSuffix(filepath.Base(page), ".html")
		files := append([]string{}, shared...)
		files = append(files, page)
		templates[name] = template.Must(template.New("").Funcs(funcMap).ParseFiles(files...))
	}
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

	tmpl := templates[templateName]
	if tmpl == nil {
		return c.Status(500).SendString("template not found: " + templateName)
	}

	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return tmpl.ExecuteTemplate(c.Context().Response.BodyWriter(), templateName+".html", data)
}

func RegisterRoutes(app *fiber.App) {
	h := &HomeHandler{}
	u := &UploadHandler{}
	a := &AnalysisHandler{}
	d := &DashboardHandler{}
	r := &ReportsHandler{}
	api := &APIHandler{}

	app.Get("/", h.Home)
	app.Get("/how-it-works", func(c *fiber.Ctx) error {
		return RenderTemplate(c, "how-it-works", nil)
	})
	app.Get("/upload", u.UploadPage)
	app.Get("/analysis/:id", a.AnalysisPage)
	app.Get("/results/:id", d.ResultsPage)
	app.Get("/reports/:id", r.ReportsPage)
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	apiGroup := app.Group("/api")
	apiGroup.Post("/upload", rateLimiter.Limit, u.Upload)
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
