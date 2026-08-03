package services

import (
	"black-hat/models"
	"os/exec"
	"strings"
)

type GitleaksRunner struct{}

func NewGitleaksRunner() *GitleaksRunner {
	return &GitleaksRunner{}
}

func (g *GitleaksRunner) Run(projectPath string) []models.SecurityFinding {
	var findings []models.SecurityFinding

	cmd := exec.Command("gitleaks", "detect", "--source", projectPath, "--report-format", "json", "--no-banner")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return findings
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "RuleID") {
		return findings
	}

	entries := strings.Split(outputStr, "\"RuleID\":")
	for _, entry := range entries[1:] {
		finding := models.SecurityFinding{
			Tool:     "gitleaks",
			Rule:     extractJSONValue(entry, "RuleID"),
			FilePath: extractJSONValue(entry, "File"),
			Severity: "high",
		}
		if finding.Rule != "" {
			finding.Description = "Secret detected: " + finding.Rule
			finding.Recommendation = "Remove the secret from the code and rotate the credentials"
		} else {
			finding.Description = "Potential secret detected in code"
			finding.Recommendation = "Review the code and remove any hardcoded secrets"
		}
		if lineNum := extractJSONValue(entry, "StartLine"); lineNum != "" {
			finding.Description += " (line " + lineNum + ")"
		}
		findings = append(findings, finding)
	}

	return findings
}
