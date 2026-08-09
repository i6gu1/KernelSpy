package services

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"black-hat/models"
)

// ESLintRunner scans JavaScript/TypeScript projects with ESLint configured with
// security plugins (eslint-plugin-security, eslint-config-airbnb, etc. are
// resolved from the project or a global install). Messages whose ruleId begins
// with "security/" are treated as security findings; everything else becomes a
// quality finding, with metrics derived from well-known rule families.
type ESLintRunner struct{}

func NewESLintRunner() *ESLintRunner {
	return &ESLintRunner{}
}

// eslintOutput mirrors the ESLint JSON formatter output (an array of files).
type eslintOutput struct {
	FilePaths []eslintFile `json:"-"`
}

type eslintFile struct {
	FilePath string          `json:"filePath"`
	Messages []eslintMessage `json:"messages"`
}

type eslintMessage struct {
	RuleID   string `json:"ruleId"`
	Severity int    `json:"severity"`
	Message  string `json:"message"`
	Line     int    `json:"line"`
}

// defaultESLintConfig activates eslint-plugin-security when the uploaded
// project ships no ESLint config of its own. build.sh installs eslint@8 with
// eslint-plugin-security globally, so the plugin name resolves.
const defaultESLintConfig = `{
  "root": true,
  "env": { "browser": true, "node": true, "es2021": true },
  "parserOptions": { "ecmaVersion": "latest", "sourceType": "module" },
  "plugins": ["security"],
  "extends": ["plugin:security/recommended-legacy"],
  "rules": {}
}
`

// ensureConfig writes a default .eslintrc.json into the project directory when
// the project has no ESLint config, so the security plugins are actually used.
// Projects that configure ESLint via a .eslintrc* / eslint.config.* file or the
// "eslintConfig" field of package.json are left untouched (an injected
// .eslintrc.json would otherwise take precedence and override their config).
func ensureESLintConfig(projectPath string) {
	existing := []string{
		".eslintrc", ".eslintrc.json", ".eslintrc.js", ".eslintrc.cjs",
		"eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
	}
	for _, name := range existing {
		if _, err := os.Stat(filepath.Join(projectPath, name)); err == nil {
			return
		}
	}
	if data, err := os.ReadFile(filepath.Join(projectPath, "package.json")); err == nil {
		var pkg struct {
			ESLintConfig json.RawMessage `json:"eslintConfig"`
		}
		if json.Unmarshal(data, &pkg) == nil && len(pkg.ESLintConfig) > 0 && string(pkg.ESLintConfig) != "null" {
			return
		}
	}
	os.WriteFile(filepath.Join(projectPath, ".eslintrc.json"), []byte(defaultESLintConfig), 0o644)
}

func (e *ESLintRunner) Run(projectPath string) ([]models.SecurityFinding, []models.QualityFinding, models.QualityMetrics) {
	var security []models.SecurityFinding
	var quality []models.QualityFinding
	metrics := models.QualityMetrics{}

	// Run eslint on the project, honoring the project's own config when it has
	// one and injecting the security-plugin config otherwise.
	ensureESLintConfig(projectPath)
	out, ok := runTool("eslint", "--format", "json", "--quiet", projectPath)
	if !ok || len(out) == 0 {
		return security, quality, metrics
	}

	var files []eslintFile
	if err := json.Unmarshal(out, &files); err != nil {
		log.Printf("[eslint] failed to parse output: %v", err)
		return security, quality, metrics
	}

	for _, f := range files {
		for _, m := range f.Messages {
			if m.Message == "" {
				continue
			}
			ruleID := m.RuleID
			if ruleID == "" {
				ruleID = "eslint"
			}
			severity := "low"
			if m.Severity >= 2 {
				severity = "high"
			} else if m.Severity == 1 {
				severity = "medium"
			}

			if isSecurityRule(ruleID) {
				security = append(security, models.SecurityFinding{
					Rule:           ruleID,
					FilePath:       relPath(projectPath, f.FilePath),
					LineNumber:     m.Line,
					Severity:       severity,
					Description:    m.Message,
					Recommendation: "Fix the violation reported by ESLint rule " + ruleID + ".",
					Tool:           "eslint",
				})
			} else {
				quality = append(quality, models.QualityFinding{
					Category:    ruleID,
					FilePath:    relPath(projectPath, f.FilePath),
					LineNumber:  m.Line,
					Severity:    severity,
					Description: m.Message,
					Tool:        "eslint",
				})
				trackMetric(&metrics, ruleID)
			}
		}
	}

	return security, quality, metrics
}

// isSecurityRule reports whether an ESLint rule id belongs to a security
// plugin (security/*, no-secrets/*, eslint-plugin-security, etc.).
func isSecurityRule(ruleID string) bool {
	lower := ruleID
	for _, prefix := range []string{"security/", "no-secrets/", "detect-", "no-eval", "no-implied-eval", "no-new-func", "no-script-url", "no-unsafe-regex", "xss/"} {
		if len(lower) >= len(prefix) && lower[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// trackMetric buckets common ESLint rules into the quality metrics schema.
func trackMetric(m *models.QualityMetrics, ruleID string) {
	switch ruleID {
	case "no-unused-vars":
		m.UnusedVars++
	case "no-unused-imports", "@typescript-eslint/no-unused-vars":
		m.UnusedImports++
	case "no-duplicate-imports", "no-dupe-keys":
		m.DuplicatedCode++
	case "complexity", "no-cond-assign":
		m.ComplexFunctions++
	case "max-lines", "max-lines-per-function":
		m.LargeFiles++
	case "max-depth", "max-nested-callbacks":
		m.LongFunctions++
	case "no-unreachable", "no-constant-condition":
		m.DeadCode++
	default:
		m.StyleIssues++
	}
}
