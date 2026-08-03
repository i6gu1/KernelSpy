package main

import (
	"html/template"
	"log"
	"os"
	"strings"

	"black-hat/config"
	"black-hat/database"
	"black-hat/handlers"
	"black-hat/i18n"
	"black-hat/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

var tmpl *template.Template

func init() {
	funcMap := template.FuncMap{
		"t": func(lang, key string) string {
			return i18n.GetInstance().Translate(lang, key)
		},
		"raw": func(s string) template.HTML {
			return template.HTML(s)
		},
	}

	tmpl = template.Must(template.New("").Funcs(funcMap).ParseGlob("templates/**/*.html"))
	tmpl = template.Must(tmpl.ParseGlob("templates/*.html"))
}

func main() {
	cfg := config.Load()

	i18n.GetInstance()

	if cfg.DatabaseURL != "" {
		if err := database.InitPostgres(cfg.DatabaseURL); err != nil {
			log.Printf("Warning: PostgreSQL not available: %v", err)
		} else {
			if err := database.RunMigrations(); err != nil {
				log.Printf("Warning: Migration failed: %v", err)
			}
		}
	}

	if cfg.RedisURL != "" {
		database.InitRedis(cfg.RedisURL)
	}

	app := fiber.New(fiber.Config{
		AppName:      "Black Hat",
		ServerHeader: "Black Hat",
		Views:        tmpl,
	})

	app.Use(logger.New())
	app.Use(recover.New())
	app.Use(compress.New())
	app.Use(middleware.SecurityHeaders)
	app.Use(middleware.I18nMiddleware)

	app.Static("/static", "./static")

	handlers.RegisterRoutes(app)

	os.MkdirAll("./uploads", 0755)

	port := cfg.Port
	if port == "" {
		port = "3000"
	}

	log.Printf("Black Hat starting on port %s", port)
	log.Fatal(app.Listen(":" + port))
}

func getLanguageFromCookie(c *fiber.Ctx) string {
	lang := c.Cookies("lang")
	if lang != "" && isValidLang(lang) {
		return lang
	}
	return "en"
}

func isValidLang(lang string) bool {
	validLangs := []string{"en", "ar", "ru", "fr", "es"}
	for _, l := range validLangs {
		if l == lang {
			return true
		}
	}
	return false
}

func getTemplateFiles(dir string) []string {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return files
	}
	for _, entry := range entries {
		if entry.IsDir() {
			subFiles := getTemplateFiles(dir + "/" + entry.Name())
			files = append(files, subFiles...)
		} else if strings.HasSuffix(entry.Name(), ".html") {
			files = append(files, dir+"/"+entry.Name())
		}
	}
	return files
}
