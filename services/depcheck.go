package services

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"

	"black-hat/models"
)

// DependencyCheckRunner wraps OWASP Dependency-Check, an SCA tool that scans
// package manifests (npm, pip, maven, gradle, nuget, composer, gem, cargo,
// go.mod, ...) and matches them against the NVD CVE feed.
//
// Operational notes:
//   - Requires a JVM (openjdk-17-jre-headless in the Docker image) and, on
//     first run, downloads the NVD data feed — that first run can take several
//     minutes (DEPCHECK_TIMEOUT_SECONDS raises the cap). Persist
//     /opt/dependency-check/data as a volume (see docker-compose.yml) so the
//     NVD cache survives restarts.
//   - Failures (no JVM, no network, NVD feed unavailable) are recorded in the
//     report as an "error" status instead of silently reporting zero CVEs.
//   - DEPENDENCY_CHECK_HOME points at the install root whose bin/ holds the
//     dependency-check.sh launcher.
//   - DEPCHECK_EXTRA_ARGS can add flags, e.g. "--disableRetireJS" for
//     fully-offline environments.
type DependencyCheckRunner struct{}

func NewDependencyCheckRunner() *DependencyCheckRunner {
	return &DependencyCheckRunner{}
}

// depCheckReport mirrors the fields of dependency-check-report.json.
type depCheckReport struct {
	Dependencies []struct {
		FileName string `json:"fileName"`
		Version  string `json:"version"`
		Package  struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"package"`
		Vulnerabilities []struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Cvssv3   struct {
				BaseSeverity string `json:"baseSeverity"`
			} `json:"cvssv3"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"vulnerabilities"`
	} `json:"dependencies"`
}

// Run executes Dependency-Check and maps its JSON report to dependency
// vulnerabilities. It is language-agnostic and runs for every project.
func (d *DependencyCheckRunner) Run(projectPath string, status *ToolStatusCollector) []models.DependencyVulnerability {
	// The launcher is a shell script (bin/dependency-check.sh) in the release
	// zip; the dependency-check wrapper in bin/ also works. Resolve whichever
	// is present.
	name := "dependency-check.sh"
	if !toolAvailable(name) {
		name = "dependency-check"
		if !toolAvailable(name) {
			status.Record(&ToolOutcome{
				Tool:   "dependency-check",
				Status: statusMissing,
				Error:  "dependency-check is not available in this deployment (serverless containers skip the JVM/NVD download; the full Docker image installs it via build.sh)",
			})
			return nil
		}
	}

	outDir, err := os.MkdirTemp("", "depcheck-out-")
	if err != nil {
		status.Record(&ToolOutcome{
			Tool:   "dependency-check",
			Status: statusError,
			Error:  "failed to create dependency-check workspace: " + err.Error(),
		})
		return nil
	}
	defer os.RemoveAll(outDir)

	args := []string{
		"--scan", projectPath,
		"--format", "JSON",
		"--out", outDir,
		"--project", "black-hat-scan",
	}
	if extra := os.Getenv("DEPCHECK_EXTRA_ARGS"); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}

	out, outcome := runToolEnv("", nil, depcheckTimeout, name, args...)
	defer func() { status.Record(outcome) }()

	if outcome.Status != statusSuccess {
		if outcome.Status != statusMissing && len(out) > 0 {
			outcome.Error = truncate(string(out), 300)
		}
		return nil
	}

	reportPath := filepath.Join(outDir, "dependency-check-report.json")
	data, readErr := readFileContent(reportPath)
	if readErr != nil {
		outcome.Status = statusError
		outcome.Error = "dependency-check finished but no report was produced: " + truncate(string(out), 300)
		log.Printf("[dependency-check] %s", outcome.Error)
		return nil
	}

	var parsed depCheckReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse dependency-check report: " + truncate(string(data), 300)
		log.Printf("[dependency-check] %s", outcome.Error)
		return nil
	}

	var vulns []models.DependencyVulnerability
	for _, dep := range parsed.Dependencies {
		pkgName := dep.Package.Name
		if pkgName == "" {
			pkgName = dep.FileName
		}
		if pkgName == "" {
			continue
		}
		version := dep.Version
		if version == "" {
			version = dep.Package.Version
		}
		for _, v := range dep.Vulnerabilities {
			if v.Name == "" {
				continue
			}
			severity := v.Severity
			if severity == "" {
				severity = v.Cvssv3.BaseSeverity
			}
			ref := ""
			if len(v.References) > 0 {
				ref = v.References[0].URL
			}
			vulns = append(vulns, models.DependencyVulnerability{
				PackageName:      pkgName,
				InstalledVersion: version,
				Severity:         normalizeSeverity(severity),
				ReferenceURL:     ref,
				Tool:             "dependency-check",
			})
		}
	}

	outcome.Findings = len(vulns)
	return vulns
}
