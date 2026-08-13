package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"black-hat/models"
)

// BrakemanRunner scans Ruby on Rails applications with Brakeman (MIT), the
// gold-standard free security scanner for Rails: SQL injection, command
// injection, mass assignment, XSS, deserialization and RCE vulnerabilities.
// Findings are reported as security issues.
//
// Brakeman analyzes Rails apps specifically, so the runner gates itself on
// Rails indicators (a Gemfile that declares rails, or an app/ tree). Non-
// Rails Ruby projects get an honest "skipped" status instead of a crash.
type BrakemanRunner struct{}

func NewBrakemanRunner() *BrakemanRunner { return &BrakemanRunner{} }

// isRailsApp reports whether the project looks like a Rails application.
func isRailsApp(projectPath string) bool {
	gemfile := filepath.Join(projectPath, "Gemfile")
	if data, err := os.ReadFile(gemfile); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "rails") {
			return true
		}
	}
	appDir := filepath.Join(projectPath, "app")
	if info, err := os.Stat(appDir); err == nil && info.IsDir() {
		return true
	}
	return false
}

// brakemanWarning mirrors one element of `brakeman -f json` warnings[].
type brakemanWarning struct {
	WarningType string   `json:"warning_type"`
	Message     string   `json:"message"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Confidence  string   `json:"confidence"`
	Code        string   `json:"code"`
	CWEID       []int    `json:"cwe_id"`
	CheckName   string   `json:"check_name"`
}

type brakemanReport struct {
	Warnings []brakemanWarning `json:"warnings"`
}

func (b *BrakemanRunner) Run(projectPath string, status *ToolStatusCollector) []models.SecurityFinding {
	outcome := &ToolOutcome{Tool: "brakeman"}
	defer func() { status.Record(outcome) }()

	if !isRailsApp(projectPath) {
		outcome.Status = statusSkipped
		outcome.Error = "no Rails application detected (Gemfile with rails or app/ tree); Brakeman only analyzes Rails apps"
		return nil
	}

	// -q silences the progress banner; --no-progress keeps output JSON-only.
	output, o := runToolInDir(projectPath, "brakeman", "--no-progress", "-q", "-f", "json", projectPath)
	*outcome = *o
	outcome.Tool = "brakeman"
	if outcome.Status != statusSuccess {
		return nil
	}

	var rep brakemanReport
	if err := json.Unmarshal(output, &rep); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse brakeman output: " + truncate(err.Error(), 200)
		return nil
	}

	// Critical warning classes are always severe regardless of confidence.
	criticalTypes := map[string]bool{
		"SQL Injection": true, "Command Injection": true, "Remote Code Execution": true,
		"Deserialization": true, "Path Traversal": true, "Unsafe Reflection": true,
	}

	findings := make([]models.SecurityFinding, 0, len(rep.Warnings))
	for _, w := range rep.Warnings {
		if w.Message == "" {
			continue
		}
		sev := "low"
		switch strings.ToLower(w.Confidence) {
		case "high":
			sev = "high"
		case "medium":
			sev = "medium"
		}
		if criticalTypes[w.WarningType] {
			sev = "high"
		}
		rec := "Review and remediate the Rails security issue flagged by Brakeman (" + w.CheckName + ")."
		if len(w.CWEID) > 0 {
			rec += " See CWE-" + strconv.Itoa(w.CWEID[0]) + ": https://cwe.mitre.org/data/definitions/" + strconv.Itoa(w.CWEID[0]) + ".html"
		}

		findings = append(findings, models.SecurityFinding{
			Rule:           "brakeman." + slug(w.CheckName),
			FilePath:       relPath(projectPath, w.File),
			LineNumber:     w.Line,
			Severity:       sev,
			Description:    w.Message + " [" + strings.TrimSpace(w.Code) + "]",
			Recommendation: rec,
			Tool:           "brakeman",
		})
	}

	outcome.Findings = len(findings)
	return findings
}

// slug lowercases and dashes a check name ("SQL" -> "sql").
func slug(s string) string {
	if s == "" {
		return "finding"
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", "-"))
}
