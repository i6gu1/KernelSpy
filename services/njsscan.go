package services

import (
	"encoding/json"
	"log"

	"black-hat/models"
)

// NjsScanRunner scans Node.js projects with Njsscan and maps its nodes to
// security findings (prototype pollution, path traversal, command injection,
// SSRF, unsafe deserialization, etc.).
type NjsScanRunner struct{}

func NewNjsScanRunner() *NjsScanRunner {
	return &NjsScanRunner{}
}

// njsscanOutput mirrors the relevant fields of `njsscan --json` output.
type njsscanOutput struct {
	Nodes []struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Filename    string `json:"filename"`
		Line        int    `json:"line"`
		Severity    string `json:"severity"`
		Rule        struct {
			ID string `json:"id"`
		} `json:"rule"`
	} `json:"nodes"`
}

func (n *NjsScanRunner) Run(projectPath string, status *ToolStatusCollector) []models.SecurityFinding {
	out, outcome := runTool("njsscan", "--json", projectPath)
	defer func() { status.Record(outcome) }()

	if outcome.Status != statusSuccess || len(out) == 0 {
		return nil
	}

	var parsed njsscanOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse njsscan output: " + truncate(string(out), 300)
		log.Printf("[njsscan] %s", outcome.Error)
		return nil
	}

	findings := make([]models.SecurityFinding, 0, len(parsed.Nodes))
	for _, node := range parsed.Nodes {
		title := node.Title
		if title == "" {
			title = node.Rule.ID
		}
		if title == "" {
			continue
		}
		description := node.Description
		if description == "" {
			description = "Security issue detected by Njsscan"
		}
		findings = append(findings, models.SecurityFinding{
			Rule:           title,
			FilePath:       relPath(projectPath, node.Filename),
			LineNumber:     node.Line,
			Severity:       normalizeSeverity(node.Severity),
			Description:    description,
			Recommendation: "Review the affected code path and apply the remediation suggested by the Njsscan rule.",
			Tool:           "njsscan",
		})
	}

	outcome.Findings = len(findings)
	return findings
}
