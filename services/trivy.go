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
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			PrimaryURL       string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// Run executes `trivy fs` and maps its JSON output to dependency findings.
//
// Invocation notes:
//   - TRIVY_CACHE_DIR is pointed at a writable, ideally persistent location.
//     On first run trivy downloads its vulnerability DB from the network; if
//     that fails (offline serverless sandbox, no disk cache), the run errors
//     and the failure is recorded in the report instead of silently returning
//     zero findings.
//   - --scanners vuln,secret,misconfig extends the scan beyond lockfiles so a
//     bare project still gets checked for embedded secrets and misconfigs.
func (t *TrivyRunner) Run(projectPath string, status *ToolStatusCollector) []models.DependencyVulnerability {
	var env []string
	if cacheDir := trivyCacheDir(); cacheDir != "" {
		env = append(env, "TRIVY_CACHE_DIR="+cacheDir)
	}

	out, outcome := runToolEnv("", env, toolTimeout, "trivy",
		"fs", "--format", "json", "--quiet",
		"--scanners", "vuln,secret,misconfig",
		"--skip-dirs", "node_modules", "--skip-dirs", ".git",
		"--exit-code", "0",
		projectPath)
	defer func() { status.Record(outcome) }()

	if outcome.Status != statusSuccess || len(out) == 0 {
		// A failed trivy (e.g. vulnerability DB could not be downloaded) is
		// recorded as an error by runToolEnv; an empty scan with exit 0 is
		// genuinely clean. Either way there are no findings to report.
		return nil
	}

	var parsed trivyOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse trivy output: " + truncate(string(out), 300)
		log.Printf("[trivy] %s", outcome.Error)
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

	outcome.Findings = len(vulns)
	return vulns
}
