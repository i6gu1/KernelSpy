package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"black-hat/models"
)

// CheckovRunner scans Infrastructure-as-Code with Checkov (Apache-2.0, by
// Bridgecrew/Prisma Cloud): Terraform, CloudFormation, Kubernetes manifests,
// Helm charts, Dockerfiles and serverless configs against 1000+ security and
// compliance policies (public exposure, encryption, RBAC, secrets, ...).
// Findings are reported as security issues.
//
// It only runs when the project contains IaC files (.tf, .hcl, Dockerfile,
// docker-compose, k8s/helm manifests, CloudFormation, serverless.yml) and
// records a "skipped" status otherwise.
type CheckovRunner struct{}

func NewCheckovRunner() *CheckovRunner { return &CheckovRunner{} }

// iacExtensions are the file types that are ALWAYS treated as Infrastructure-
// as-Code (yaml/json need an additional filename hint to count as IaC).
var iacExtensions = map[string]bool{
	".tf": true, ".tfvars": true, ".hcl": true,
}

// containsIaCFiles reports whether the project ships any Infrastructure-as-
// Code that Checkov can scan.
func containsIaCFiles(projectPath string) bool {
	found := false
	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || found {
			return nil
		}
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		base := strings.ToLower(filepath.Base(path))
		switch {
		case base == "dockerfile" || strings.HasPrefix(base, "dockerfile."),
			strings.HasPrefix(base, "docker-compose"),
			base == "chart.yaml", strings.HasPrefix(base, "values"),
			base == "serverless.yml" || base == "serverless.yaml",
			strings.HasSuffix(base, ".cloudformation.json") || strings.HasSuffix(base, ".template.yaml"):
			found = true
		case iacExtensions[strings.ToLower(filepath.Ext(path))]:
			found = true
		case ext == ".yaml" || ext == ".yml" || ext == ".json":
			// Heuristic: only treat yaml/json as IaC when the filename hints
			// at k8s/cloudformation to avoid running the heavy scanner on
			// every generic config file in a source project.
			if strings.Contains(base, "k8s") || strings.Contains(base, "kube") ||
				strings.Contains(base, "deployment") || strings.Contains(base, "service") ||
				strings.Contains(base, "ingress") || strings.Contains(base, "configmap") ||
				strings.Contains(base, "statefulset") || strings.Contains(base, "cronjob") ||
				strings.Contains(base, "cloudformation") || strings.HasSuffix(base, ".template.yaml") {
				found = true
			}
		}
		return nil
	})
	return found
}

// checkovFailedCheck mirrors one element of checkov's results.failed_checks.
type checkovFailedCheck struct {
	CheckID    string   `json:"check_id"`
	CheckName  string   `json:"check_name"`
	File       string   `json:"file"`
	LineRange  []int    `json:"file_line_range"`
	Resource   string   `json:"resource"`
	Severity   string   `json:"severity"`
	Guideline  string   `json:"guideline"`
	Fix        string   `json:"fix"`
}

type checkovReport struct {
	Results struct {
		FailedChecks []checkovFailedCheck `json:"failed_checks"`
	} `json:"results"`
}

func (c *CheckovRunner) Run(projectPath string, status *ToolStatusCollector) []models.SecurityFinding {
	outcome := &ToolOutcome{Tool: "checkov"}
	defer func() { status.Record(outcome) }()

	if !containsIaCFiles(projectPath) {
		outcome.Status = statusSkipped
		outcome.Error = "no Infrastructure-as-Code files detected (terraform/k8s/docker/compose); skipping Checkov"
		return nil
	}

	// --download-external-modules is a boolean flag and defaults to OFF, so it
	// is deliberately not passed ("--download-external-modules false" would
	// ENABLE it and make checkov fetch external Terraform modules).
	output, o := runToolInDir(projectPath, "checkov", "-d", ".", "-o", "json", "--quiet", "--compact")
	*outcome = *o
	outcome.Tool = "checkov"
	if outcome.Status != statusSuccess {
		return nil
	}

	var rep checkovReport
	if err := json.Unmarshal(output, &rep); err != nil {
		outcome.Status = statusError
		outcome.Error = "failed to parse checkov output: " + truncate(err.Error(), 200)
		return nil
	}

	findings := make([]models.SecurityFinding, 0, len(rep.Results.FailedChecks))
	for _, f := range rep.Results.FailedChecks {
		if f.CheckName == "" {
			continue
		}
		sev := normalizeSeverity(f.Severity)
		line := 0
		if len(f.LineRange) > 0 {
			line = f.LineRange[0]
		}
		desc := f.CheckName + " (" + f.CheckID + ")"
		if f.Resource != "" {
			desc += " — " + f.Resource
		}
		rec := "Remediate the IaC misconfiguration " + f.CheckID
		if f.Fix != "" {
			rec += ": " + f.Fix
		}
		if f.Guideline != "" {
			rec += " — " + f.Guideline
		}
		findings = append(findings, models.SecurityFinding{
			Rule:           "checkov." + f.CheckID,
			FilePath:       relPath(projectPath, f.File),
			LineNumber:     line,
			Severity:       sev,
			Description:    truncate(desc, 300),
			Recommendation: truncate(rec, 300),
			Tool:           "checkov",
		})
	}

	outcome.Findings = len(findings)
	return findings
}
