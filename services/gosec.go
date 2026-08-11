package services

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"

	"black-hat/models"
)

// GosecRunner scans Go projects with Gosec (-fmt json) and maps its issues to
// security findings (hardcoded credentials, SQL injection, unsafe file/exec
// handling, TLS misconfiguration, etc.).
type GosecRunner struct{}

func NewGosecRunner() *GosecRunner {
	return &GosecRunner{}
}

// gosecOutput mirrors the relevant fields of `gosec -fmt json` output.
type gosecOutput struct {
	Issues []struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Details  string `json:"details"`
		File     string `json:"file"`
		Line     string `json:"line"`
		Code     string `json:"code"`
	} `json:"Issues"`
}

func (g *GosecRunner) Run(projectPath string, status *ToolStatusCollector) []models.SecurityFinding {
	// Gosec must run inside a Go module. If the project has no go.mod there is
	// nothing to scan; the run errors and that is recorded, not hidden.
	out, outcome := runToolInDir(projectPath, "gosec", "-fmt", "json", "-quiet", "./...")
	defer func() { status.Record(outcome) }()

	if outcome.Status != statusSuccess || len(out) == 0 {
		return nil
	}

	var parsed gosecOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse gosec output: " + truncate(string(out), 300)
		log.Printf("[gosec] %s", outcome.Error)
		return nil
	}

	findings := make([]models.SecurityFinding, 0, len(parsed.Issues))
	for _, issue := range parsed.Issues {
		if issue.RuleID == "" {
			continue
		}
		line, _ := strconv.Atoi(issue.Line)
		description := strings.TrimSpace(issue.Details)
		if description == "" {
			description = "Security issue detected by Gosec: " + issue.RuleID
		}
		findings = append(findings, models.SecurityFinding{
			Rule:           issue.RuleID,
			FilePath:       relPath(projectPath, issue.File),
			LineNumber:     line,
			Severity:       normalizeSeverity(issue.Severity),
			Description:    description,
			Recommendation: "Apply the fix suggested by the Gosec rule (" + issue.RuleID + ").",
			Tool:           "gosec",
		})
	}

	outcome.Findings = len(findings)
	return findings
}
