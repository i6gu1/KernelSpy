package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"black-hat/models"
)

// TestAnalyzeVulnerablePythonProject is the regression test for the
// false-negative bug: a deliberately vulnerable Python file must produce
// findings when Bandit is installed, and when a scanner is missing its status
// must be recorded so the report can never claim "clean" without the scanners
// having actually run.
func TestAnalyzeVulnerablePythonProject(t *testing.T) {
	dir := t.TempDir()
	vuln := `import sqlite3

def get_user(name):
    con = sqlite3.connect("app.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()

API_KEY = "sk-1234567890abcdef1234567890abcdef"
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(vuln), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := NewAnalyzer().AnalyzeProject(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Fail-safe #1: every language-agnostic scanner must have a recorded
	// status — a missing tool is visible, never silently dropped.
	if len(res.ToolStatuses) == 0 {
		t.Fatal("no tool statuses recorded; the fail-safe report is missing")
	}

	statusByTool := map[string]models.ToolStatus{}
	codeqlRecorded := false
	for _, st := range res.ToolStatuses {
		statusByTool[st.Tool] = st
		if strings.HasPrefix(st.Tool, "codeql") {
			codeqlRecorded = true
		}
	}
	for _, tool := range []string{"semgrep", "gitleaks", "trivy", "dependency-check"} {
		if _, ok := statusByTool[tool]; !ok {
			t.Errorf("expected a recorded status for %q", tool)
		}
	}
	if !codeqlRecorded {
		t.Error("expected a recorded status for a codeql scan (codeql(...))")
	}

	// Fail-safe #0 (regression for the serverless false-negative bug): the
	// built-in pattern analyzer runs with zero external dependencies and must
	// ALWAYS be recorded as a successful scanner, so a Vercel/serverless
	// deployment still produces a real report.
	builtinStatus, ok := statusByTool["builtin"]
	if !ok {
		t.Fatal("builtin analyzer status not recorded")
	}
	if builtinStatus.Status != statusSuccess {
		t.Errorf("builtin analyzer must report success (got %s)", builtinStatus.Status)
	}

	bandit, ok := statusByTool["bandit"]
	if !ok {
		t.Fatal("bandit status not recorded")
	}

	// Fail-safe #2: if the applicable scanner ran, it must find the planted
	// SQL injection / hardcoded secret. If it could not run, the summary must
	// say the scan is INCOMPLETE instead of reporting a clean result.
	// (The built-in analyzer makes findings non-empty regardless, but the
	// INCOMPLETE warning must still surface whenever a tool was missing.)
	if bandit.Status == statusSuccess {
		if len(res.SecurityFindings) == 0 {
			t.Error("bandit ran successfully but found NOTHING on a deliberately vulnerable file — false negative")
		}
	} else {
		if strings.Contains(res.Summary, "No vulnerabilities were detected by the static analysis tools") {
			t.Errorf("summary hides that bandit could not run (status=%s): %s", bandit.Status, res.Summary)
		}
		if !strings.Contains(res.Summary, "INCOMPLETE") {
			t.Errorf("summary should warn the scan is incomplete when a scanner failed (status=%s): %s", bandit.Status, res.Summary)
		}
	}
}
