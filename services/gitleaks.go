package services

import (
	"encoding/json"
	"log"
	"os"
	"strconv"

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

func (g *GitleaksRunner) Run(projectPath string, status *ToolStatusCollector) []models.SecurityFinding {
	// Gitleaks exits non-zero when leaks are found; the JSON report is written
	// to a unique temp file, so we parse that instead of stdout.
	reportFile, err := os.CreateTemp("", "gitleaks-report-*.json")
	if err != nil {
		status.Record(&ToolOutcome{
			Tool:   "gitleaks",
			Status: statusError,
			Error:  "failed to create gitleaks report file: " + err.Error(),
		})
		return nil
	}
	reportPath := reportFile.Name()
	reportFile.Close()
	defer removeFile(reportPath)

	// Exit code 1 is gitleaks' *designed* "leaks found" signal — not a
	// failure. runToolEnv classifies it as statusError only when the process
	// also produced no output, so flip that one case back to success here.
	// A genuinely missing binary is still recorded as statusMissing.
	_, outcome := runTool("gitleaks", "detect", "--source", projectPath,
		"--report-format", "json", "--report-path", reportPath, "--no-banner")
	if outcome != nil && outcome.Status == statusError && outcome.ExitCode == 1 {
		outcome.Status = statusSuccess
		outcome.Error = ""
	}
	defer func() { status.Record(outcome) }()

	data, readErr := readFileContent(reportPath)
	if readErr != nil || len(data) == 0 {
		// No report file: exit 0 means genuinely no leaks. A non-zero exit with
		// no report is a real gitleaks failure — record it instead of reporting
		// a clean scan.
		if outcome != nil && outcome.Status != statusMissing && outcome.ExitCode != 0 {
			outcome.Status = statusError
			outcome.Error = "gitleaks exited with code " + strconv.Itoa(outcome.ExitCode) + " but produced no report"
		}
		return nil
	}

	var findings []gitleaksFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse gitleaks report: " + truncate(string(data), 300)
		log.Printf("[gitleaks] %s", outcome.Error)
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
			FilePath:       relPath(projectPath, f.File),
			LineNumber:     f.StartLine,
			Severity:       "high",
			Description:    description,
			Recommendation: "Remove the secret from the code, rotate the credential, and use a secrets manager.",
			Tool:           "gitleaks",
		})
	}

	outcome.Findings = len(result)
	return result
}
