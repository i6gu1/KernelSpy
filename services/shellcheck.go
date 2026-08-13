package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"black-hat/models"
)

// ShellCheckRunner scans shell scripts (sh/bash/zsh) with ShellCheck, the
// definitive free static analyzer for shell code (GPL-3.0). It catches
// quoting errors, unquoted variable expansions, unsafe eval patterns and
// portability bugs. Findings are reported as code-quality issues.
//
// The runner only runs when the project actually contains shell scripts and
// records a "skipped" status otherwise (a shell-free project must not show a
// spurious missing/error status). On Vercel serverless the tool is typically
// not installed, so the status surfaces as "missing" — honest, never a
// false clean scan.
type ShellCheckRunner struct{}

func NewShellCheckRunner() *ShellCheckRunner { return &ShellCheckRunner{} }

// shellFiles returns the project's shell scripts, capped so a pathological
// project cannot produce a multi-thousand-argument invocation.
func shellFiles(projectPath string) []string {
	var files []string
	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") || strings.Contains(path, "vendor") {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".sh", ".bash", ".zsh":
			files = append(files, path)
		}
		return nil
	})
	if len(files) > 200 {
		files = files[:200]
	}
	return files
}

// shellcheckFinding mirrors one element of `shellcheck -f json`.
type shellcheckFinding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Level   string `json:"level"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *ShellCheckRunner) Run(projectPath string, status *ToolStatusCollector) ([]models.QualityFinding, models.QualityMetrics) {
	outcome := &ToolOutcome{Tool: "shellcheck"}
	defer func() { status.Record(outcome) }()

	files := shellFiles(projectPath)
	if len(files) == 0 {
		outcome.Status = statusSkipped
		outcome.Error = "no .sh/.bash/.zsh scripts found in the project"
		return nil, models.QualityMetrics{}
	}

	args := append([]string{"-f", "json"}, files...)
	output, o := runToolInDir(projectPath, "shellcheck", args...)
	*outcome = *o
	outcome.Tool = "shellcheck"
	if outcome.Status != statusSuccess {
		return nil, models.QualityMetrics{}
	}

	var list []shellcheckFinding
	if err := json.Unmarshal(output, &list); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse shellcheck output: " + truncate(err.Error(), 200)
		return nil, models.QualityMetrics{}
	}

	findings := make([]models.QualityFinding, 0, len(list))
	for _, f := range list {
		if f.Message == "" {
			continue
		}
		sev := "low"
		switch f.Level {
		case "error":
			sev = "high"
		case "warning":
			sev = "medium"
		}
		findings = append(findings, models.QualityFinding{
			Tool:        "shellcheck",
			FilePath:    relPath(projectPath, f.File),
			LineNumber:  f.Line,
			Severity:    sev,
			Description: f.Message,
			Category:    "shellcheck SC" + strconv.Itoa(f.Code),
		})
	}

	outcome.Findings = len(findings)
	return findings, models.QualityMetrics{}
}
