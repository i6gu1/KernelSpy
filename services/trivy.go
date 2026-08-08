package services

import (
	"encoding/json"
	"log"

	"black-hat/models"
)

// TrivyRunner scans project filesystems for known vulnerabilities in
// dependencies (OS packages, languages such as Go/npm/pip/composer, IaC, etc.)
// using `trivy fs --format json`.
type TrivyRunner struct{}

func NewTrivyRunner() *TrivyRunner {
	return &TrivyRunner{}
}

// trivyOutput mirrors the relevant fields of `trivy fs --format json`.
type trivyOutput struct {
	Results []struct {
		Target           string `json:"Target"`
		Vulnerabilities  []struct {
			VulnerabilityID   string `json:"VulnerabilityID"`
			PkgName           string `json:"PkgName"`
			InstalledVersion  string `json:"InstalledVersion"`
			FixedVersion      string `json:"FixedVersion"`
			Severity          string `json:"Severity"`
			PrimaryURL        string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func (t *TrivyRunner) Run(projectPath string) []models.DependencyVulnerability {
	out, ok := runTool("trivy", "fs", "--format", "json", "--quiet", "--skip-dirs", "node_modules", "--skip-dirs", ".git", projectPath)
	if !ok || len(out) == 0 {
		return nil
	}

	var parsed trivyOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		log.Printf("[trivy] failed to parse output: %v", err)
		return nil
	}

	var vulns []models.DependencyVulnerability
	for _, r := range parsed.Results {
		for _, v := range r.Vulnerabilities {
			if v.VulnerabilityID == "" || v.PkgName == "" {
				continue
			}
			vulns = append(vulns, models.DependencyVulnerability{
				PackageName:      v.PkgName,
				InstalledVersion: v.InstalledVersion,
				PatchedVersion:   v.FixedVersion,
				Severity:         normalizeSeverity(v.Severity),
				ReferenceURL:     v.PrimaryURL,
				Tool:             "trivy",
			})
		}
	}

	return vulns
}
