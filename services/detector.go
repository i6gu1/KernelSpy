package services

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Detector identifies the programming languages, package ecosystems, frameworks
// and configuration files present in an extracted project. The analyzer uses
// this to decide which scanners to run: languages drive the language-specific
// runners (Gosec, Bandit, ESLint, ...), ecosystems tell the SCA tools (Trivy,
// OWASP Dependency-Check) which package managers to expect, and every finding
// is later mapped back onto the project root.
type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

// languageExtensions maps source-file extensions onto the canonical language
// names the analyzer switches on. HTML/CSS are included because template
// injection and style-based CSP issues are in scope for the polyglot scanners.
var languageExtensions = map[string]string{
	".go":     "go",
	".js":     "javascript",
	".ts":     "typescript",
	".jsx":    "javascript",
	".tsx":    "typescript",
	".py":     "python",
	".java":   "java",
	".rs":     "rust",
	".php":    "php",
	".rb":     "ruby",
	".c":      "c",
	".cpp":    "cpp",
	".h":      "c",
	".hpp":    "cpp",
	".cs":     "csharp",
	".swift":  "swift",
	".kt":     "kotlin",
	".kts":    "kotlin",
	".scala":  "scala",
	".lua":    "lua",
	".r":      "r",
	".R":      "r",
	".m":      "objective-c",
	".mm":     "objective-c",
	".vue":    "javascript",
	".svelte": "javascript",
	".html":   "html",
	".htm":    "html",
	".css":    "css",
	".scss":   "css",
	".sass":   "css",
	".less":   "css",
}

// manifestLanguages maps dependency manifests / lockfiles onto the language
// they imply. A project that ships package.json but no .js files (e.g. a
// transpiled frontend, or a Java project built via Gradle with only
// build.gradle) is still detected as that language.
var manifestLanguages = map[string]string{
	"package.json":      "javascript",
	"package-lock.json": "javascript",
	"yarn.lock":         "javascript",
	"pnpm-lock.yaml":    "javascript",
	"bun.lockb":         "javascript",
	"deno.json":         "javascript",
	"requirements.txt":  "python",
	"Pipfile":           "python",
	"Pipfile.lock":      "python",
	"pyproject.toml":    "python",
	"poetry.lock":       "python",
	"go.mod":            "go",
	"go.sum":            "go",
	"Cargo.toml":        "rust",
	"Cargo.lock":        "rust",
	"pom.xml":           "java",
	"build.gradle":      "java",
	"build.gradle.kts":  "java",
	"settings.gradle":   "java",
	"composer.json":     "php",
	"composer.lock":     "php",
	"Gemfile":           "ruby",
	"Gemfile.lock":      "ruby",
}

// DetectLanguages walks the project tree and returns the sorted set of
// languages present, inferred from BOTH source-file extensions and dependency
// manifests, so a project is detected correctly even when it contains no
// source files of the manifest's language (e.g. a JS project compiled away).
func (d *Detector) DetectLanguages(projectPath string) []string {
	langMap := make(map[string]bool)
	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") || strings.Contains(path, "vendor") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if lang, ok := languageExtensions[ext]; ok {
			langMap[lang] = true
		}
		baseName := filepath.Base(path)
		if lang, ok := manifestLanguages[baseName]; ok {
			langMap[lang] = true
		}
		if strings.HasSuffix(baseName, ".csproj") || strings.HasSuffix(baseName, ".sln") {
			langMap["csharp"] = true
		}
		return nil
	})
	return sortedKeys(langMap)
}

// ecosystemManifests maps manifests/lockfiles onto the package-ecosystem name
// used by the SCA scanners (Trivy `fs`, Dependency-Check analyzers).
var ecosystemManifests = map[string]string{
	"package.json":     "npm",
	"yarn.lock":        "yarn",
	"pnpm-lock.yaml":   "pnpm",
	"requirements.txt": "pip",
	"Pipfile":          "pipenv",
	"Pipfile.lock":     "pipenv",
	"pyproject.toml":   "pip",
	"poetry.lock":      "poetry",
	"go.mod":           "go",
	"go.sum":           "go",
	"Cargo.toml":       "cargo",
	"Cargo.lock":       "cargo",
	"pom.xml":          "maven",
	"build.gradle":     "gradle",
	"build.gradle.kts": "gradle",
	"settings.gradle":  "gradle",
	"composer.json":    "composer",
	"composer.lock":    "composer",
	"Gemfile":          "rubygems",
	"Gemfile.lock":     "rubygems",
	"packages.config":  "nuget",
}

// DetectEcosystems returns the sorted set of package ecosystems detected from
// the project's manifests and lockfiles (npm, pip, maven, cargo, ...).
func (d *Detector) DetectEcosystems(projectPath string) []string {
	ecoMap := make(map[string]bool)
	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") {
			return nil
		}
		baseName := filepath.Base(path)
		if eco, ok := ecosystemManifests[baseName]; ok {
			ecoMap[eco] = true
		}
		if strings.HasSuffix(baseName, ".csproj") {
			ecoMap["nuget"] = true
		}
		return nil
	})
	return sortedKeys(ecoMap)
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

	return sortedKeys(frameworkMap)
}

func (d *Detector) DetectConfigFiles(projectPath string) []string {
	configFiles := []string{}
	configNames := map[string]bool{
		"package.json":       true,
		"go.mod":             true,
		"requirements.txt":   true,
		"Pipfile":            true,
		"pyproject.toml":     true,
		"Cargo.toml":         true,
		"pom.xml":            true,
		"build.gradle":       true,
		"composer.json":      true,
		"Gemfile":            true,
		"Makefile":           true,
		"Dockerfile":         true,
		"docker-compose.yml": true,
		".env":               true,
		".gitignore":         true,
		"tsconfig.json":      true,
		".eslintrc":          true,
		".prettierrc":        true,
		"webpack.config.js":  true,
		"vite.config.js":     true,
		"vite.config.ts":     true,
		"next.config.js":     true,
		"angular.json":       true,
		"vue.config.js":      true,
		"rust-toolchain":     true,
		"jest.config.js":     true,
		"vitest.config.ts":   true,
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

// sortedKeys returns the map keys sorted, so detection results are
// deterministic across runs and hosts (map iteration order is random in Go).
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
