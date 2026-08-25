package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
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

	// WriteTimeout must exceed the analysis deadline so the HTTP response
	// is never killed while runAnalysis is still executing. The default
	// analysis deadline is 600 s (10 min); honour the same ANALYSIS_TIMEOUT
	// env var the handler uses and add a 60 s buffer.
	writeTimeout := 11 * time.Minute
	if v := os.Getenv("ANALYSIS_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			writeTimeout = time.Duration(n+60) * time.Second
		}
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handlers.NewHandler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("KernelSpy starting on port %s (uploads in %s)", port, os.TempDir())
	log.Fatal(srv.ListenAndServe())
}
