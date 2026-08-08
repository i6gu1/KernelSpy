package handlers

import (
	"bytes"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"black-hat"
	"black-hat/i18n"
	"black-hat/middleware"
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

	tplFS := assets.Templates()

	var shared []string
	shared = append(shared, getTemplateFiles(tplFS, "layouts")...)
	shared = append(shared, getTemplateFiles(tplFS, "components")...)
	shared = append(shared, getTemplateFiles(tplFS, "partials")...)

	for _, page := range getTemplateFiles(tplFS, "pages") {
		name := strings.TrimSuffix(filepath.Base(page), ".html")
		files := append([]string{}, shared...)
		files = append(files, page)
		templates[name] = template.Must(template.New("").Funcs(funcMap).ParseFS(tplFS, files...))
	}
}

// RenderTemplate renders a page into the response, resolving the language and
// text direction from the request context (set by I18nMiddleware).
func RenderTemplate(w http.ResponseWriter, r *http.Request, templateName string, data map[string]interface{}) {
	lang := middleware.LangFrom(r)
	dir := middleware.DirFrom(r)

	if data == nil {
		data = make(map[string]interface{})
	}
	data["Lang"] = lang
	data["Dir"] = dir
	data["CurrentPage"] = templateName

	tmpl := templates[templateName]
	if tmpl == nil {
		http.Error(w, "template not found: "+templateName, http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, templateName+".html", data); err != nil {
		log.Printf("template render error: %v", err)
		http.Error(w, "template render error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func getTemplateFiles(tplFS fs.FS, dir string) []string {
	var files []string
	fs.WalkDir(tplFS, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".html") {
			files = append(files, path)
		}
		return nil
	})
	return files
}

// NewHandler builds the full HTTP handler (pages + API + static assets) and
// wraps it with the middleware chain. This is the single entry point used by
// both the local server (main.go) and the Vercel Go function (api/handler.go).
func NewHandler() http.Handler {
	mux := http.NewServeMux()

	h := &HomeHandler{}
	u := &UploadHandler{}
	a := &AnalysisHandler{}
	d := &DashboardHandler{}
	r := &ReportsHandler{}
	api := &APIHandler{}

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(assets.Static()))))

	mux.HandleFunc("/", h.Home)
	mux.HandleFunc("/how-it-works", func(w http.ResponseWriter, r *http.Request) {
		RenderTemplate(w, r, "how-it-works", nil)
	})
	mux.HandleFunc("/upload", u.UploadPage)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
	})

	mux.Handle("/analysis/", http.HandlerFunc(a.AnalysisPage))
	mux.Handle("/results/", http.HandlerFunc(d.ResultsPage))
	mux.Handle("/reports/", http.HandlerFunc(r.ReportsPage))

	mux.Handle("/api/upload", rateLimiter.Limit(http.HandlerFunc(u.Upload)))
	mux.Handle("/api/analysis/status/", http.HandlerFunc(api.AnalysisStatus))
	mux.Handle("/api/results/security/", http.HandlerFunc(api.SecurityResults))
	mux.Handle("/api/results/quality/", http.HandlerFunc(api.QualityResults))
	mux.Handle("/api/results/dependencies/", http.HandlerFunc(api.DependencyResults))
	mux.Handle("/api/reports/", http.HandlerFunc(r.DownloadReport))

	return middleware.Recover(middleware.SecurityHeaders(middleware.I18nMiddleware(mux)))
}
