package services

import (
	"black-hat/models"
	"os/exec"
	"strings"
)

type GolangCIRunner struct{}

func NewGolangCIRunner() *GolangCIRunner {
	return &GolangCIRunner{}
}

func (g *GolangCIRunner) Run(projectPath string, status *ToolStatusCollector) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	output, outcome := runTool("golangci-lint", "run", "--out-format", "json", projectPath+"/...")
	defer func() { status.Record(outcome) }()

	if outcome.Status != statusSuccess {
		// The real linter could not run (missing/timeout/crash): record that
		// in the status and fall back to the lightweight heuristic scan so the
		// report still shows quality signal instead of nothing.
		return g.generateDefaultFindings(projectPath)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "Issues") {
		return g.generateDefaultFindings(projectPath)
	}

	parts := strings.Split(outputStr, "\"Text\":")
	for _, part := range parts[1:] {
		finding := models.QualityFinding{
			Tool:        "golangci-lint",
			Description: extractJSONValue(part, "Text"),
			FilePath:    relPath(projectPath, extractJSONValue(part, "Filename")),
			Category:    "quality",
			Severity:    "medium",
		}
		if linter := extractJSONValue(part, "FromLinter"); linter != "" {
			finding.Description = "[" + linter + "] " + finding.Description
		}
		findings = append(findings, finding)
		metrics.StyleIssues++
	}

	outcome.Findings = len(findings)
	return findings, metrics
}

func (g *GolangCIRunner) generateDefaultFindings(projectPath string) ([]models.QualityFinding, models.QualityMetrics) {
	var findings []models.QualityFinding
	var metrics models.QualityMetrics

	cmd := exec.Command("find", projectPath, "-name", "*.go")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return findings, metrics
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, file := range files {
		if file == "" || strings.Contains(file, "vendor") {
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
				Tool:        "golangci-lint",
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
						Tool:        "golangci-lint",
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
