package services

import (
	"encoding/json"
	"log"

	"black-hat/models"
)

// SemgrepRunner scans projects with Semgrep (--config=auto) and unmarshals its
// JSON output. Covers XSS, SQL/command injection, SSRF, path traversal and
// hundreds of other rules across all major languages.
type SemgrepRunner struct{}

func NewSemgrepRunner() *SemgrepRunner {
	return &SemgrepRunner{}
}

// semgrepOutput mirrors the relevant fields of `semgrep --json` output.
type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
		} `json:"extra"`
	} `json:"results"`
	Errors []interface{} `json:"errors"`
}

func (s *SemgrepRunner) Run(projectPath string) []models.SecurityFinding {
	out, ok := runTool("semgrep", "--config=auto", "--json", "--quiet", projectPath)
	if !ok || len(out) == 0 {
		return nil
	}

	var parsed semgrepOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		log.Printf("[semgrep] failed to parse output: %v", err)
		return nil
	}

	findings := make([]models.SecurityFinding, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		if r.CheckID == "" {
			continue
		}
		description := r.Extra.Message
		if description == "" {
			description = "Security issue detected by Semgrep"
		}
		findings = append(findings, models.SecurityFinding{
			Rule:           r.CheckID,
			FilePath:       relPath(projectPath, r.Path),
			LineNumber:     r.Start.Line,
			Severity:       normalizeSeverity(r.Extra.Severity),
			Description:    description,
			Recommendation: "Review the code and apply the fix suggested by the Semgrep rule.",
			Tool:           "semgrep",
		})
	}

	return findings
}
