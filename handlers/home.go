package handlers

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"black-hat"
	"black-hat/i18n"
	"black-hat/middleware"
)

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

// siteURL returns the public origin of the deployment, used for canonical
// URLs, Open Graph tags, JSON-LD and the sitemap. Override with the SITE_URL
// env var (e.g. your custom domain); defaults to the Vercel deployment.
func siteURL() string {
	if v := os.Getenv("SITE_URL"); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	return "https://kernelspy.vercel.app"
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
	data["SiteURL"] = siteURL()
	// Clean the request path so canonical tags never carry "..", "//" or
	// encoded noise (the raw URL.Path is decoded and uncleaned).
	data["Canonical"] = siteURL() + path.Clean(r.URL.Path)

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
// the local server and the Vercel Go server preset (cmd/api/main.go binds it
// to $PORT).
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
	mux.HandleFunc("/privacy", func(w http.ResponseWriter, r *http.Request) {
		RenderTemplate(w, r, "privacy", nil)
	})
	mux.HandleFunc("/upload", u.UploadPage)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		middleware.WriteJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
	})

	// Technical SEO: robots.txt and the XML sitemap, both generated from the
	// same SITE_URL the canonical tags use, so crawlers see one consistent
	// origin.
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fmt.Fprintf(w, "User-agent: *\nAllow: /\n\nSitemap: %s/sitemap.xml\n", siteURL())
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		base := siteURL()
		// Public, indexable pages only — analysis results are ephemeral
		// per-instance data and must never be crawled.
		pages := []struct{ path, lastmod string }{
			{"/", time.Now().Format("2006-01-02")},
			{"/how-it-works", time.Now().Format("2006-01-02")},
			{"/upload", time.Now().Format("2006-01-02")},
			{"/privacy", time.Now().Format("2006-01-02")},
		}
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n"))
		w.Write([]byte(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n"))
		for _, p := range pages {
			fmt.Fprintf(w, "  <url>\n    <loc>%s%s</loc>\n    <lastmod>%s</lastmod>\n    <changefreq>weekly</changefreq>\n  </url>\n", base, p.path, p.lastmod)
		}
		w.Write([]byte(`</urlset>` + "\n"))
	})

	mux.Handle("/analysis/", http.HandlerFunc(a.AnalysisPage))
	mux.Handle("/results/", http.HandlerFunc(d.ResultsPage))
	mux.Handle("/reports/", http.HandlerFunc(r.ReportsPage))

	mux.Handle("/api/upload", http.HandlerFunc(u.Upload))
	mux.Handle("/api/upload/token", http.HandlerFunc(u.UploadToken))
	mux.Handle("/api/upload/complete", http.HandlerFunc(u.CompleteUpload))
	mux.Handle("/api/analysis/status/", http.HandlerFunc(api.AnalysisStatus))
	mux.Handle("/api/results/security/", http.HandlerFunc(api.SecurityResults))
	mux.Handle("/api/results/quality/", http.HandlerFunc(api.QualityResults))
	mux.Handle("/api/results/dependencies/", http.HandlerFunc(api.DependencyResults))
	mux.Handle("/api/reports/", http.HandlerFunc(r.DownloadReport))

	return middleware.Recover(middleware.SecurityHeaders(middleware.I18nMiddleware(mux)))
}
