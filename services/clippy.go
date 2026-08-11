package services

import (
	"black-hat/models"
	"os/exec"
	"strings"
)

type ClippyRunner struct{}

func NewClippyRunner() *ClippyRunner {
	return &ClippyRunner{}
}

func (c *ClippyRunner) Run(projectPath string, status *ToolStatusCollector) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	output, outcome := runToolInDir(projectPath, "cargo", "clippy", "--message-format=json", "--quiet")
	defer func() { status.Record(outcome) }()

	if outcome.Status != statusSuccess {
		return c.generateDefaultFindings(projectPath)
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "\"message\"") {
			continue
		}
		finding := models.QualityFinding{
			Tool:        "clippy",
			Description: extractJSONValue(line, "message"),
			Category:    "quality",
			Severity:    "medium",
		}
		if finding.Description != "" {
			findings = append(findings, finding)
			metrics.StyleIssues++
		}
	}

	outcome.Findings = len(findings)
	return findings, metrics
}

func (c *ClippyRunner) generateDefaultFindings(projectPath string) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	cmd := exec.Command("find", projectPath, "-name", "*.rs")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return findings, metrics
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, file := range files {
		if file == "" || strings.Contains(file, "target") || strings.Contains(file, ".git") {
			continue
		}
		data, err := readFileContent(file)
		if err != nil {
			continue
		}
		content := string(data)
		lines := strings.Split(content, "\n")

		totalLines := len(lines)
		if totalLines > 500 {
			metrics.LargeFiles++
			findings = append(findings, models.QualityFinding{
				Tool:        "clippy",
				FilePath:    relPath(projectPath, file),
				Description: "Large file detected",
				Category:    "large_file",
				Severity:    "low",
			})
		}

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || trimmed == "" {
				continue
			}
			if len(trimmed) > 120 {
				metrics.StyleIssues++
				if len(findings) < 50 {
					findings = append(findings, models.QualityFinding{
						Tool:        "clippy",
						FilePath:    relPath(projectPath, file),
						LineNumber:  i + 1,
						Description: "Line exceeds 120 characters",
						Category:    "style",
						Severity:    "info",
					})
				}
			}
		}
	}

	return findings, metrics
}
