package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port                  string
	Env                   string
	DatabaseURL           string
	RedisURL              string
	MaxUploadSize         int64
	UploadDir             string
	AnalysisTimeout       int
	MaxConcurrentAnalyses int
}

func Load() *Config {
	return &Config{
		Port:                  getEnv("PORT", "3000"),
		Env:                   getEnv("ENV", "development"),
		DatabaseURL:           getEnv("DATABASE_URL", ""),
		RedisURL:              getEnv("REDIS_URL", ""),
		MaxUploadSize:         getEnvInt64("MAX_UPLOAD_SIZE", 52428800),
		UploadDir:             getEnv("UPLOAD_DIR", "./uploads"),
		AnalysisTimeout:       getEnvInt("ANALYSIS_TIMEOUT", 600),
		MaxConcurrentAnalyses: getEnvInt("MAX_CONCURRENT_ANALYSES", 5),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intVal
		}
	}
	return defaultValue
}
