package services

import (
	"black-hat/models"
	"os/exec"
	"strconv"
	"strings"
)

type ESLintRunner struct{}

func NewESLintRunner() *ESLintRunner {
	return &ESLintRunner{}
}

func (e *ESLintRunner) Run(projectPath string) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	cmd := exec.Command("npx", "eslint", "--format", "json", "--quiet", projectPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return e.generateDefaultFindings(projectPath)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "messages") {
		return e.generateDefaultFindings(projectPath)
	}

	fileParts := strings.Split(outputStr, "\"filePath\":")
	for _, part := range fileParts[1:] {
		filePath := extractJSONValue(part, "filePath")
		msgParts := strings.Split(part, "\"message\":")
		for _, msg := range msgParts[1:] {
			finding := models.QualityFinding{
				Tool:        "eslint",
				FilePath:    filePath,
				Description: extractJSONValue(msg, "message"),
				Category:    "style",
				Severity:    "low",
			}
			if sev := extractJSONValue(msg, "severity"); sev == "2" {
				finding.Severity = "medium"
				finding.Category = "quality"
			}
			findings = append(findings, finding)
			metrics.StyleIssues++
		}
	}

	return findings, metrics
}

func (e *ESLintRunner) generateDefaultFindings(projectPath string) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	cmd := exec.Command("find", projectPath, "-name", "*.js", "-o", "-name", "*.ts", "-o", "-name", "*.jsx", "-o", "-name", "*.tsx")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return findings, metrics
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, file := range files {
		if file == "" || strings.Contains(file, "node_modules") || strings.Contains(file, ".git") {
			continue
		}
		data, err := readFileContent(file)
		if err != nil {
			continue
		}
		content := string(data)
		lines := strings.Split(content, "\n")

		totalLines := len(lines)
		if totalLines > 300 {
			metrics.LargeFiles++
			findings = append(findings, models.QualityFinding{
				Tool:        "eslint",
				FilePath:    file,
				Description: "File is too large (" + strconv.Itoa(totalLines) + " lines)",
				Category:    "large_file",
				Severity:    "low",
			})
		}

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if len(trimmed) > 120 {
				metrics.StyleIssues++
				if len(findings) < 50 {
					findings = append(findings, models.QualityFinding{
						Tool:        "eslint",
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

func readFileContent(path string) ([]byte, error) {
	cmd := exec.Command("cat", path)
	return cmd.Output()
}
