package services

import (
	"black-hat/models"
	"os/exec"
	"strings"
)

type TrivyRunner struct{}

func NewTrivyRunner() *TrivyRunner {
	return &TrivyRunner{}
}

func (t *TrivyRunner) Run(projectPath string) []models.DependencyVulnerability {
	var vulns []models.DependencyVulnerability

	cmd := exec.Command("trivy", "fs", "--format", "json", "--quiet", projectPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return vulns
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "Results") {
		return vulns
	}

	parts := strings.Split(outputStr, "\"Target\":")
	for _, part := range parts[1:] {
		vulnParts := strings.Split(part, "\"Vulnerabilities\":")
		if len(vulnParts) < 2 {
			continue
		}
		vulnSection := vulnParts[1]
		entries := strings.Split(vulnSection, "\"VulnerabilityID\":")
		for _, entry := range entries[1:] {
			vuln := models.DependencyVulnerability{
				Tool:             "trivy",
				InstalledVersion: extractJSONValue(entry, "InstalledVersion"),
				PatchedVersion:   extractJSONValue(entry, "FixedVersion"),
				PackageName:      extractJSONValue(entry, "PkgName"),
			}
			vuln.ReferenceURL = extractJSONValue(entry, "PrimaryURL")
			sev := strings.ToUpper(extractJSONValue(entry, "Severity"))
			switch sev {
			case "CRITICAL":
				vuln.Severity = "critical"
			case "HIGH":
				vuln.Severity = "high"
			case "MEDIUM":
				vuln.Severity = "medium"
			case "LOW":
				vuln.Severity = "low"
			default:
				vuln.Severity = "info"
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}
