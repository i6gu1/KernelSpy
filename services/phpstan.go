package services

import (
	"black-hat/models"
	"os/exec"
	"strings"
)

type PHPStanRunner struct{}

func NewPHPStanRunner() *PHPStanRunner {
	return &PHPStanRunner{}
}

func (p *PHPStanRunner) Run(projectPath string, status *ToolStatusCollector) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	output, outcome := runTool("phpstan", "analyse", projectPath, "--format=json", "--no-progress")
	defer func() { status.Record(outcome) }()

	if outcome.Status != statusSuccess {
		return p.generateDefaultFindings(projectPath)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "messages") {
		return p.generateDefaultFindings(projectPath)
	}

	fileParts := strings.Split(outputStr, "\"file\":")
	for _, part := range fileParts[1:] {
		filePath := extractJSONValue(part, "file")
		msgParts := strings.Split(part, "\"message\":")
		for _, msg := range msgParts[1:] {
			finding := models.QualityFinding{
				Tool:        "phpstan",
				FilePath:    relPath(projectPath, filePath),
				Description: extractJSONValue(msg, "message"),
				Category:    "quality",
				Severity:    "medium",
			}
			if lineNum := extractJSONValue(msg, "line"); lineNum != "" {
				finding.Description = finding.Description + " (line " + lineNum + ")"
			}
			findings = append(findings, finding)
		}
	}

	outcome.Findings = len(findings)
	return findings, metrics
}

func (p *PHPStanRunner) generateDefaultFindings(projectPath string) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	cmd := exec.Command("find", projectPath, "-name", "*.php")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return findings, metrics
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, file := range files {
		if file == "" || strings.Contains(file, "vendor") || strings.Contains(file, ".git") {
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
				Tool:        "phpstan",
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
						Tool:        "phpstan",
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
