package services

import (
	"encoding/json"
	"strings"

	"black-hat/models"
)

// CppcheckRunner scans C/C++ sources with Cppcheck (GPL-3.0), the leading
// free static analyzer for memory-safety and undefined behavior in C/C++:
// buffer overflows, memory leaks, null-pointer dereferences and data races.
// Findings are reported as security issues because memory-safety bugs are a
// primary root cause of exploitable vulnerabilities.
//
// Cppcheck has no official container image, so in docker execution mode the
// executor falls back to the native install (same as CodeQL / Dependency-
// Check / SpotBugs). It only runs when the project contains C/C++ files.
type CppcheckRunner struct{}

func NewCppcheckRunner() *CppcheckRunner { return &CppcheckRunner{} }

// cppcheckFinding mirrors one element of `cppcheck --template=json` output.
type cppcheckFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	ID       string `json:"id"`
}

func (c *CppcheckRunner) Run(projectPath string, status *ToolStatusCollector) []models.SecurityFinding {
	outcome := &ToolOutcome{Tool: "cppcheck"}
	defer func() { status.Record(outcome) }()

	output, o := runToolInDir(projectPath, "cppcheck",
		"--enable=all",
		"--template=json",
		"--quiet",
		"--suppress=missingIncludeSystem",
		".",
	)
	*outcome = *o
	outcome.Tool = "cppcheck"
	if outcome.Status != statusSuccess {
		return nil
	}

	// `--template=json` emits a JSON array; the results may be interleaved
	// with informational stderr lines, so fall back to extracting the array.
	var list []cppcheckFinding
	if err := json.Unmarshal(output, &list); err != nil {
		start, end := strings.IndexByte(string(output), '['), strings.LastIndexByte(string(output), ']')
		if start < 0 || end <= start || json.Unmarshal(output[start:end+1], &list) != nil {
			outcome.Status = statusError
			outcome.Error = "failed to parse cppcheck output: " + truncate(err.Error(), 200)
			return nil
		}
	}

	findings := make([]models.SecurityFinding, 0, len(list))
	for _, f := range list {
		if f.Message == "" || f.Severity == "information" {
			continue
		}
		sev := "low"
		switch f.Severity {
		case "error":
			sev = "high"
		case "warning":
			sev = "medium"
		case "style", "performance", "portability":
			sev = "low"
		}
		rule := "cppcheck." + f.ID
		if rule == "cppcheck." {
			rule = "cppcheck"
		}
		findings = append(findings, models.SecurityFinding{
			Rule:           rule,
			FilePath:       relPath(projectPath, f.File),
			LineNumber:     f.Line,
			Severity:       sev,
			Description:    f.Message,
			Recommendation: "Fix the C/C++ defect flagged by Cppcheck (" + f.ID + ") — memory-safety errors can be remotely exploitable.",
			Tool:           "cppcheck",
		})
	}

	outcome.Findings = len(findings)
	return findings
}
