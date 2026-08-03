package services

import (
	"black-hat/models"
	"os/exec"
	"strings"
)

type PMDRunner struct{}

func NewPMDRunner() *PMDRunner {
	return &PMDRunner{}
}

func (p *PMDRunner) Run(projectPath string) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	cmd := exec.Command("pmd", "check", "-d", projectPath, "-R", "rulesets/java/quickstart.xml", "-f", "json", "--no-cache")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return p.generateDefaultFindings(projectPath), metrics
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "violation") {
		return p.generateDefaultFindings(projectPath), metrics
	}

	parts := strings.Split(outputStr, "\"description\":")
	for _, part := range parts[1:] {
		finding := models.QualityFinding{
			Tool:        "pmd",
			Description: extractJSONValue(part, "description"),
			FilePath:    extractJSONValue(part, "filename"),
			Category:    extractJSONValue(part, "ruleset"),
			Severity:    "medium",
		}
		findings = append(findings, finding)
	}

	return findings, metrics
}

func (p *PMDRunner) generateDefaultFindings(projectPath string) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	cmd := exec.Command("find", projectPath, "-name", "*.java")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return findings, metrics
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, file := range files {
		if file == "" || strings.Contains(file, ".git") {
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
				Tool:        "pmd",
				FilePath:    file,
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
						Tool:        "pmd",
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
