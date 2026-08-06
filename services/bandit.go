package services

import (
	"black-hat/models"
	"os/exec"
	"strings"
)

type BanditRunner struct{}

func NewBanditRunner() *BanditRunner {
	return &BanditRunner{}
}

func (b *BanditRunner) Run(projectPath string) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	cmd := exec.Command("bandit", "-r", projectPath, "-f", "json", "-q")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return b.generateDefaultFindings(projectPath)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "results") {
		return b.generateDefaultFindings(projectPath)
	}

	parts := strings.Split(outputStr, "\"issue_text\":")
	for _, part := range parts[1:] {
		finding := models.QualityFinding{
			Tool:        "bandit",
			Description: extractJSONValue(part, "issue_text"),
			FilePath:    extractJSONValue(part, "filename"),
			Category:    extractJSONValue(part, "issue_type"),
			Severity:    "medium",
		}
		if sev := extractJSONValue(part, "issue_severity"); sev != "" {
			switch strings.ToUpper(sev) {
			case "HIGH":
				finding.Severity = "high"
			case "MEDIUM":
				finding.Severity = "medium"
			case "LOW":
				finding.Severity = "low"
			}
		}
		findings = append(findings, finding)
	}

	return findings, metrics
}

func (b *BanditRunner) generateDefaultFindings(projectPath string) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	cmd := exec.Command("find", projectPath, "-name", "*.py")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return findings, metrics
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, file := range files {
		if file == "" || strings.Contains(file, "node_modules") || strings.Contains(file, ".git") || strings.Contains(file, "venv") {
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
				Tool:        "bandit",
				FilePath:    file,
				Description: "Large file detected",
				Category:    "large_file",
				Severity:    "low",
			})
		}

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			if len(trimmed) > 120 {
				metrics.StyleIssues++
				if len(findings) < 50 {
					findings = append(findings, models.QualityFinding{
						Tool:        "bandit",
						FilePath:    file,
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
