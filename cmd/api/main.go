package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"black-hat/config"
	"black-hat/database"
	"black-hat/handlers"
	"black-hat/i18n"
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

	port := cfg.Port
	if port == "" {
		port = "3000"
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handlers.NewHandler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Black Hat starting on port %s (uploads in %s)", port, os.TempDir())
	log.Fatal(srv.ListenAndServe())
}
