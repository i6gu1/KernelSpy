package database

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func InitPostgres(databaseURL string) error {
	var err error
	DB, err = sql.Open("postgres", databaseURL)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if err = DB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	DB.SetMaxOpenConns(25)
	DB.SetMaxIdleConns(5)

	log.Println("Connected to PostgreSQL")
	return nil
}

func RunMigrations() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS projects (
			id SERIAL PRIMARY KEY,
			user_id INTEGER,
			name VARCHAR(255) NOT NULL,
			source_type VARCHAR(50) NOT NULL,
			source_url VARCHAR(500),
			file_path VARCHAR(500),
			status VARCHAR(50) DEFAULT 'pending',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS analyses (
			id SERIAL PRIMARY KEY,
			project_id INTEGER REFERENCES projects(id),
			status VARCHAR(50) NOT NULL,
			started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
			duration_seconds INTEGER,
			files_scanned INTEGER,
			languages_detected TEXT[],
			frameworks_detected TEXT[]
		)`,
		`CREATE TABLE IF NOT EXISTS security_findings (
			id SERIAL PRIMARY KEY,
			analysis_id INTEGER REFERENCES analyses(id),
			rule VARCHAR(255) NOT NULL,
			file_path VARCHAR(500),
			line_number INTEGER,
			severity VARCHAR(50) NOT NULL,
			description TEXT,
			recommendation TEXT,
			tool VARCHAR(100)
		)`,
		`CREATE TABLE IF NOT EXISTS quality_findings (
			id SERIAL PRIMARY KEY,
			analysis_id INTEGER REFERENCES analyses(id),
			category VARCHAR(100) NOT NULL,
			file_path VARCHAR(500),
			line_number INTEGER,
			severity VARCHAR(50),
			description TEXT,
			tool VARCHAR(100)
		)`,
		`CREATE TABLE IF NOT EXISTS dependency_vulnerabilities (
			id SERIAL PRIMARY KEY,
			analysis_id INTEGER REFERENCES analyses(id),
			package_name VARCHAR(255) NOT NULL,
			installed_version VARCHAR(100),
			patched_version VARCHAR(100),
			severity VARCHAR(50),
			reference_url VARCHAR(500),
			tool VARCHAR(100)
		)`,
		`CREATE TABLE IF NOT EXISTS reports (
			id SERIAL PRIMARY KEY,
			analysis_id INTEGER REFERENCES analyses(id),
			format VARCHAR(20) NOT NULL,
			file_path VARCHAR(500),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range queries {
		if _, err := DB.Exec(query); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	log.Println("Database migrations completed")
	return nil
}

func Close() {
	if DB != nil {
		DB.Close()
	}
}
