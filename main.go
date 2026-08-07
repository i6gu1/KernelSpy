package main

import (
	"log"
	"os"

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

func main() {
	config.LoadEnvFile(".env.local")

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
		// Vercel proxies all requests; use the forwarded header so IP-based
		// rate limiting sees the real client, not the proxy.
		ProxyHeader: "X-Forwarded-For",
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
