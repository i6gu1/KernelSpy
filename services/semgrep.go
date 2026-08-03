package services

import (
	"black-hat/models"
	"os/exec"
	"strings"
)

type SemgrepRunner struct{}

func NewSemgrepRunner() *SemgrepRunner {
	return &SemgrepRunner{}
}

func (s *SemgrepRunner) Run(projectPath string) []models.SecurityFinding {
	var findings []models.SecurityFinding

	cmd := exec.Command("semgrep", "--config=auto", "--json", "--quiet", projectPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return findings
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "results") {
		return findings
	}

	parts := strings.Split(outputStr, "\"rule\":")
	for _, part := range parts[1:] {
		finding := models.SecurityFinding{
			Tool:        "semgrep",
			Severity:    "medium",
			Description: extractJSONValue(part, "message"),
			Rule:        extractJSONValue(part, "rule"),
		}
		filePath := extractJSONValue(part, "file")
		if filePath != "" {
			finding.FilePath = filePath
		}
		sev := strings.ToLower(extractJSONValue(part, "severity"))
		switch sev {
		case "error", "critical":
			finding.Severity = "critical"
		case "warning", "high":
			finding.Severity = "high"
		case "medium", "info":
			finding.Severity = "medium"
		default:
			finding.Severity = "low"
		}
		finding.Description = extractJSONValue(part, "message")
		if finding.Description == "" {
			finding.Description = "Security issue detected by Semgrep"
		}
		finding.Recommendation = "Review the code and apply the recommended fix"
		findings = append(findings, finding)
	}

	return findings
}

func extractJSONValue(json, key string) string {
	searchKey := "\"" + key + "\":"
	idx := strings.Index(json, searchKey)
	if idx == -1 {
		return ""
	}
	rest := json[idx+len(searchKey):]
	rest = strings.TrimSpace(rest)
	if len(rest) < 2 {
		return ""
	}
	if rest[0] == '"' {
		endIdx := strings.Index(rest[1:], "\"")
		if endIdx == -1 {
			return ""
		}
		return rest[1 : endIdx+1]
	}
	return ""
}
