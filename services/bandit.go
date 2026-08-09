package services

import (
	"encoding/json"
	"log"

	"black-hat/models"
)

// BanditRunner scans Python projects with Bandit (-r -f json) and maps its
// results to security findings. Bandit is a security linter: SQL injection,
// command injection, hardcoded passwords, unsafe deserialization, etc.
type BanditRunner struct{}

func NewBanditRunner() *BanditRunner {
	return &BanditRunner{}
}

// banditOutput mirrors the relevant fields of `bandit -f json` output.
type banditOutput struct {
	Results []struct {
		TestID        string `json:"test_id"`
		TestName      string `json:"test_name"`
		IssueSeverity string `json:"issue_severity"`
		IssueText     string `json:"issue_text"`
		MoreInfo      string `json:"more_info"`
		Filename      string `json:"filename"`
		LineNumber    int    `json:"line_number"`
	} `json:"results"`
}

func (b *BanditRunner) Run(projectPath string) []models.SecurityFinding {
	out, ok := runTool("bandit", "-r", projectPath, "-f", "json", "-q")
	if !ok || len(out) == 0 {
		return nil
	}

	var parsed banditOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		log.Printf("[bandit] failed to parse output: %v", err)
		return nil
	}

	findings := make([]models.SecurityFinding, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		if r.TestID == "" && r.TestName == "" {
			continue
		}
		rule := r.TestID
		if rule == "" {
			rule = r.TestName
		}
		findings = append(findings, models.SecurityFinding{
			Rule:           rule,
			FilePath:       relPath(projectPath, r.Filename),
			LineNumber:     r.LineNumber,
			Severity:       normalizeSeverity(r.IssueSeverity),
			Description:    r.IssueText,
			Recommendation: r.MoreInfo,
			Tool:           "bandit",
		})
	}

	return findings
}
