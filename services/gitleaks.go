package services

import (
	"encoding/json"
	"log"
	"os"

	"black-hat/models"
)

// GitleaksRunner scans for hardcoded secrets (API keys, AWS keys, tokens,
// passwords) with Gitleaks and maps its JSON report to security findings.
type GitleaksRunner struct{}

func NewGitleaksRunner() *GitleaksRunner {
	return &GitleaksRunner{}
}

// gitleaksFinding mirrors one entry of the Gitleaks JSON report.
type gitleaksFinding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	File        string `json:"File"`
	Secret      string `json:"Secret"`
	Match       string `json:"Match"`
}

func (g *GitleaksRunner) Run(projectPath string) []models.SecurityFinding {
	// Gitleaks exits non-zero when leaks are found; the JSON report is written
	// to a unique temp file, so we parse that instead of stdout.
	reportFile, err := os.CreateTemp("", "gitleaks-report-*.json")
	if err != nil {
		return nil
	}
	reportPath := reportFile.Name()
	reportFile.Close()
	defer removeFile(reportPath)

	// Gitleaks exits with code 1 when it finds leaks — that is its designed
	// behavior, not a failure — so the ok flag from runTool must NOT gate the
	// report parsing. Findings live in the report file, which may be the only
	// output. If the tool is missing, the temp file stays empty and the
	// len(data)==0 check below returns nil gracefully.
	runTool("gitleaks", "detect", "--source", projectPath,
		"--report-format", "json", "--report-path", reportPath, "--no-banner")

	data, readErr := readFileContent(reportPath)
	if readErr != nil || len(data) == 0 {
		return nil
	}

	var findings []gitleaksFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		log.Printf("[gitleaks] failed to parse report: %v", err)
		return nil
	}

	var result []models.SecurityFinding
	for _, f := range findings {
		if f.RuleID == "" {
			continue
		}
		description := f.Description
		if description == "" {
			description = "Secret detected: " + f.RuleID
		}
		result = append(result, models.SecurityFinding{
			Rule:           f.RuleID,
			FilePath:       f.File,
			LineNumber:     f.StartLine,
			Severity:       "high",
			Description:    description,
			Recommendation: "Remove the secret from the code, rotate the credential, and use a secrets manager.",
			Tool:           "gitleaks",
		})
	}

	return result
}
