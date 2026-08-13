package services

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"black-hat/models"
)

// SemgrepRunner scans projects with Semgrep (--config=auto by default) and
// unmarshals its JSON output. Covers XSS, SQL/command injection, SSRF, path
// traversal and hundreds of other rules across all major languages.
type SemgrepRunner struct{}

func NewSemgrepRunner() *SemgrepRunner {
	return &SemgrepRunner{}
}

// semgrepOutput mirrors the relevant fields of `semgrep --json` output.
type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
		} `json:"extra"`
	} `json:"results"`
	Errors []interface{} `json:"errors"`
}

// Run executes semgrep and maps its JSON findings to the unified schema.
//
// Invocation notes (these are the classic silent-failure traps):
//   - --metrics=off plus SEMGREP_SEND_METRICS=off: semgrep >= 1.0 blocks
//     non-interactive runs unless metrics collection is disabled.
//   - --disable-version-check: avoids an extra network round-trip.
//   - --config=auto downloads rules from the semgrep registry (needs network).
//     Point SEMGREP_CONFIG at a local rules directory (--config=<dir>) for
//     fully offline deployments.
//   - semgrep exits 1 when findings exist; runToolEnv classifies "exit != 0
//     with output" as success, so findings are parsed normally.
func (s *SemgrepRunner) Run(projectPath string, status *ToolStatusCollector) []models.SecurityFinding {
	// Default to the p/security-audit ruleset: it is the high-signal security
	// pack and, unlike --config=auto, it works with metrics disabled (auto
	// refuses to run when SEMGREP_SEND_METRICS=off/--metrics=off). Set
	// SEMGREP_CONFIG=auto for the full auto rule set, or point it at a local
	// rules directory for fully-offline runs.
	config := os.Getenv("SEMGREP_CONFIG")
	if config == "" {
		config = "p/security-audit"
	}

	// --config=auto (and p/... registry packs) require metrics consent; only
	// the auto config is told about metrics handling explicitly so it can run.
	args := []string{"--config=" + config, "--json", "--quiet",
		"--disable-version-check", "--timeout=30", "--jobs=2"}
	var env []string
	if !strings.Contains(config, "auto") {
		args = append(args, "--metrics=off")
		env = append(env, "SEMGREP_SEND_METRICS=off")
	}
	args = append(args, projectPath)

	out, outcome := runToolEnv("", env, toolTimeout, "semgrep", args...)
	defer func() { status.Record(outcome) }()

	if outcome.Status != statusSuccess || len(out) == 0 {
		return nil
	}

	var parsed semgrepOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		// Common cause: --config=auto failed to download rules and semgrep
		// wrote a plain-text error instead of JSON. Surface that, don't hide it.
		outcome.Status = statusError
		outcome.Error = "failed to parse semgrep output (network/rules download failure?): " + truncate(string(out), 300)
		log.Printf("[semgrep] %s", outcome.Error)
		return nil
	}

	// Valid JSON but semgrep itself reported errors (e.g. rules failed to
	// load when running --config=auto offline). Findings from the rules that
	// did run are still returned, but the status is downgraded so the report
	// can never claim a clean scan.
	if len(parsed.Errors) > 0 {
		outcome.Status = statusError
		outcome.Error = fmt.Sprintf("semgrep reported %d error(s) while scanning (e.g. failed to download rules); findings may be incomplete", len(parsed.Errors))
		log.Printf("[semgrep] %s", outcome.Error)
	}

	findings := make([]models.SecurityFinding, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		if r.CheckID == "" {
			continue
		}
		description := r.Extra.Message
		if description == "" {
			description = "Security issue detected by Semgrep"
		}
		findings = append(findings, models.SecurityFinding{
			Rule:           r.CheckID,
			FilePath:       relPath(projectPath, r.Path),
			LineNumber:     r.Start.Line,
			Severity:       normalizeSeverity(r.Extra.Severity),
			Description:    description,
			Recommendation: "Review the code and apply the fix suggested by the Semgrep rule.",
			Tool:           "semgrep",
		})
	}

	outcome.Findings = len(findings)
	return findings
}
