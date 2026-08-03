package services

import (
	"os"
	"path/filepath"
	"strings"
)

type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

func (d *Detector) DetectLanguages(projectPath string) []string {
	langMap := make(map[string]bool)
	extensions := map[string]string{
		".go":    "go",
		".js":    "javascript",
		".ts":    "typescript",
		".jsx":   "javascript",
		".tsx":   "typescript",
		".py":    "python",
		".java":  "java",
		".rs":    "rust",
		".php":   "php",
		".rb":    "ruby",
		".c":     "c",
		".cpp":   "cpp",
		".h":     "c",
		".cs":    "csharp",
		".swift": "swift",
		".kt":    "kotlin",
		".scala": "scala",
		".lua":   "lua",
		".r":     "r",
		".R":     "r",
		".m":     "objective-c",
		".vue":   "javascript",
		".svelte": "javascript",
	}

	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") || strings.Contains(path, "vendor") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if lang, ok := extensions[ext]; ok {
			langMap[lang] = true
		}
		return nil
	})

	var languages []string
	for lang := range langMap {
		languages = append(languages, lang)
	}
	return languages
}

func (d *Detector) DetectFrameworks(projectPath string) []string {
	frameworkMap := make(map[string]bool)
	indicators := map[string][]string{
		"react":       {"react", "jsx", "tsx", ".react"},
		"vue":         {"vue.config", "nuxt.config", ".vue"},
		"angular":     {"angular.json", "@angular"},
		"next":        {"next.config", "next.config.js", "next.config.ts"},
		"nuxt":        {"nuxt.config"},
		"svelte":      {"svelte.config", ".svelte"},
		"express":     {"express", "app.js", "server.js"},
		"fastify":     {"fastify"},
		"gin":         {"gin-gonic", "github.com/gin-gonic"},
		"fiber":       {"gofiber", "github.com/gofiber"},
		"django":      {"django", "manage.py", "settings.py"},
		"flask":       {"flask", "app.py"},
		"fastapi":     {"fastapi"},
		"spring":      {"spring", "pom.xml"},
		"laravel":     {"laravel", "artisan"},
		"rails":       {"rails", "Gemfile"},
		"rails_api":   {"rails"},
		"rails_full":  {"rails"},
		"rust_actix":  {"actix-web"},
		"rust_rocket": {"rocket"},
		"dotnet":      {".csproj", ".sln"},
	}

	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") {
			return nil
		}
		baseName := strings.ToLower(filepath.Base(path))
		for framework, patterns := range indicators {
			for _, pattern := range patterns {
				if strings.Contains(baseName, pattern) {
					frameworkMap[framework] = true
					break
				}
			}
		}
		return nil
	})

	var frameworks []string
	for fw := range frameworkMap {
		frameworks = append(frameworks, fw)
	}
	return frameworks
}

func (d *Detector) DetectConfigFiles(projectPath string) []string {
	configFiles := []string{}
	configNames := map[string]bool{
		"package.json":     true,
		"go.mod":           true,
		"requirements.txt": true,
		"Pipfile":          true,
		"pyproject.toml":   true,
		"Cargo.toml":       true,
		"pom.xml":          true,
		"build.gradle":     true,
		"composer.json":    true,
		"Gemfile":          true,
		"Makefile":         true,
		"Dockerfile":       true,
		"docker-compose.yml": true,
		".env":             true,
		".gitignore":       true,
		"tsconfig.json":    true,
		".eslintrc":        true,
		".prettierrc":      true,
		"webpack.config.js": true,
		"vite.config.js":   true,
		"vite.config.ts":   true,
		"next.config.js":   true,
		"angular.json":     true,
		"vue.config.js":    true,
		"rust-toolchain":   true,
		"jest.config.js":   true,
		"vitest.config.ts": true,
	}

	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") {
			return nil
		}
		baseName := filepath.Base(path)
		if configNames[baseName] {
			relPath, _ := filepath.Rel(projectPath, path)
			configFiles = append(configFiles, relPath)
		}
		return nil
	})

	return configFiles
}
