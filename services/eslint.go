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

// ensureESLintConfig writes a default .eslintrc.json into the project directory
// when the project has no ESLint config, so the security plugins are actually
// used, and reports whether the config was injected. Projects that configure
// ESLint via a .eslintrc* / eslint.config.* file or the "eslintConfig" field of
// package.json are left untouched (an injected .eslintrc.json would otherwise
// take precedence and override their config) and false is returned.
func ensureESLintConfig(projectPath string) bool {
	existing := []string{
		".eslintrc", ".eslintrc.json", ".eslintrc.js", ".eslintrc.cjs",
		"eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
	}
	for _, name := range existing {
		if _, err := os.Stat(filepath.Join(projectPath, name)); err == nil {
			return false
		}
	}
	if data, err := os.ReadFile(filepath.Join(projectPath, "package.json")); err == nil {
		var pkg struct {
			ESLintConfig json.RawMessage `json:"eslintConfig"`
		}
		if json.Unmarshal(data, &pkg) == nil && len(pkg.ESLintConfig) > 0 && string(pkg.ESLintConfig) != "null" {
			return false
		}
	}
	os.WriteFile(filepath.Join(projectPath, ".eslintrc.json"), []byte(defaultESLintConfig), 0o644)
	return true
}

func (e *ESLintRunner) Run(projectPath string, status *ToolStatusCollector) ([]models.SecurityFinding, []models.QualityFinding, models.QualityMetrics) {
	var security []models.SecurityFinding
	var quality []models.QualityFinding
	metrics := models.QualityMetrics{}

	// Run eslint on the project, honoring the project's own config when it has
	// one and injecting the security-plugin config otherwise. The working
	// directory must be the project itself: scanning an absolute path from
	// another cwd makes eslint's internal ignore/path handling choke
	// ("path should be a path.relative()d string").
	//
	// build.sh installs eslint@8 + plugins into a self-contained prefix
	// (/opt/eslint). We pass --resolve-plugins-relative-to so the security
	// plugins resolve from that prefix even though the project dir has no
	// node_modules — without it a globally-installed plugin set can be
	// invisible to eslint ("couldn't find the plugin" errors).
	injectedConfig := ensureESLintConfig(projectPath)
	args := []string{"--format", "json", "--quiet"}
	// Only pin plugin resolution to the global prefix when we injected the
	// default config: a project with its own ESLint config resolves its own
	// (possibly local) plugins and must not be redirected to /opt/eslint.
	if injectedConfig {
		if prefix := eslintPrefix(); prefix != "" {
			args = append(args, "--resolve-plugins-relative-to", prefix)
		}
	}
	args = append(args, ".")
	out, outcome := runToolInDir(projectPath, "eslint", args...)
	defer func() { status.Record(outcome) }()

	if outcome.Status != statusSuccess || len(out) == 0 {
		return security, quality, metrics
	}

	var files []eslintFile
	if err := json.Unmarshal(out, &files); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse eslint output: " + truncate(string(out), 300)
		log.Printf("[eslint] %s", outcome.Error)
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

	outcome.Findings = len(security) + len(quality)
	return security, quality, metrics
}

// eslintPrefix returns the prefix directory that holds the global eslint
// install (and its plugins): the ESLINT_PREFIX env var when set, otherwise the
// prefix derived from the resolved eslint binary (e.g. /opt/bin/eslint ->
// /opt/eslint/bin/eslint -> /opt/eslint). The empty string means no dedicated
// prefix was found; eslint then falls back to resolving plugins relative to
// the project dir, which works when the project ships its own plugins.
func eslintPrefix() string {
	// The ESLINT_PREFIX env var is the authoritative source when set (build.sh
	// bakes it into the image). It must contain node_modules/eslint to be
	// usable as a --resolve-plugins-relative-to base.
	if p := os.Getenv("ESLINT_PREFIX"); p != "" {
		if _, err := os.Stat(filepath.Join(p, "node_modules", "eslint")); err == nil {
			return p
		}
	}

	// Fall back to deriving the prefix from the resolved eslint binary. npm
	// install --prefix puts eslint at <prefix>/node_modules/eslint/bin/eslint.js
	// (and a .bin/eslint symlink), so follow symlinks then walk up until we
	// find the directory that contains node_modules/eslint.
	bin := findTool("eslint")
	if bin == "" {
		return ""
	}
	if real, err := filepath.EvalSymlinks(bin); err == nil {
		bin = real
	}
	dir := filepath.Dir(bin)
	for {
		if _, err := os.Stat(filepath.Join(dir, "node_modules", "eslint")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
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
