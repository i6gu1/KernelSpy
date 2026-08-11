package services

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"black-hat/models"
)

// Tool outcome statuses. These are the only values a ToolOutcome.Status can
// take, and the exact strings the frontend/report renders as badges.
const (
	statusSuccess = "success"
	statusMissing = "missing"
	statusTimeout = "timeout"
	statusError   = "error"
	statusSkipped = "skipped" // intentionally disabled by configuration
)

// toolTimeout bounds every SAST tool invocation so a hung scanner can never
// stall the pipeline forever. Override with SAST_TOOL_TIMEOUT_SECONDS.
var toolTimeout = func() time.Duration {
	if s := os.Getenv("SAST_TOOL_TIMEOUT_SECONDS"); s != "" {
		if d, err := time.ParseDuration(s + "s"); err == nil {
			return d
		}
	}
	return 300 * time.Second
}()

// codeqlTimeout bounds each CodeQL database-create / analyze step. CodeQL is
// far slower than the other tools, so it gets its own (larger) budget.
// Override with CODQL_TIMEOUT_SECONDS.
var codeqlTimeout = func() time.Duration {
	if s := os.Getenv("CODQL_TIMEOUT_SECONDS"); s != "" {
		if d, err := time.ParseDuration(s + "s"); err == nil {
			return d
		}
	}
	return 10 * time.Minute
}()

// depcheckTimeout bounds each OWASP Dependency-Check run. The first run also
// downloads the NVD data feed, which can take several minutes.
// Override with DEPCHECK_TIMEOUT_SECONDS.
var depcheckTimeout = func() time.Duration {
	if s := os.Getenv("DEPCHECK_TIMEOUT_SECONDS"); s != "" {
		if d, err := time.ParseDuration(s + "s"); err == nil {
			return d
		}
	}
	return 10 * time.Minute
}()

// ToolOutcome describes how a single tool invocation ended. Every runner must
// hand its outcome to the scan's ToolStatusCollector so the final report shows
// exactly which scanners ran, which were skipped because they are not
// installed, and which failed or timed out. A scanner that cannot run is NEVER
// reported as "no findings" — that would be a false negative.
type ToolOutcome struct {
	Tool     string
	Status   string
	Error    string
	ExitCode int
	Duration time.Duration
	Findings int // set by the runner after it parses the report
} // findTool locates a SAST binary. It checks, in order:
//  1. CODQL_HOME / DEPENDENCY_CHECK_HOME for the heavy tools (their real
//     install trees — a bare symlink would break their launchers, which
//     locate lib/ via dirname $0)
//  2. the SAST_TOOLS_DIR environment variable (custom install path)
//  3. /opt/bin and /usr/local/bin (the directories build.sh installs into)
//  4. the PATH
//
// Returning "" means the tool is not installed; runners then record a
// "missing" status so the report explains why that scanner contributed
// nothing, instead of silently reporting a clean result.
func findTool(name string) string {
	var candidates []string

	if home := os.Getenv("CODQL_HOME"); home != "" && name == "codeql" {
		candidates = append(candidates, filepath.Join(home, name))
	}
	if home := os.Getenv("DEPENDENCY_CHECK_HOME"); home != "" && strings.HasPrefix(name, "dependency-check") {
		candidates = append(candidates, filepath.Join(home, "bin", name))
	}
	if dir := os.Getenv("SAST_TOOLS_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, name))
	}
	if runtime.GOOS != "windows" {
		candidates = append(candidates,
			filepath.Join("/opt/bin", name),
			filepath.Join("/usr/local/bin", name),
		)
		if name == "codeql" {
			candidates = append(candidates, filepath.Join("/opt/codeql", name))
		}
		if strings.HasPrefix(name, "dependency-check") {
			candidates = append(candidates, filepath.Join("/opt/dependency-check/bin", name))
		}
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// runTool runs a discovered tool and returns its combined output plus an
// outcome describing how the invocation ended. A nil outcome never happens —
// a missing binary is reported as statusMissing, a crash as statusError, a
// hang as statusTimeout. Non-zero exit codes that still produced output (e.g.
// semgrep exits 1 when it finds issues, gitleaks exits 1 on leaks) are
// treated as success: the caller decides whether that output is a report or
// an error message.
func runTool(name string, args ...string) ([]byte, *ToolOutcome) {
	return runToolEnv("", nil, toolTimeout, name, args...)
}

// runToolInDir runs a tool with the given working directory (used by tools
// like gosec/golangci-lint that need a module context). An empty dir is
// equivalent to the process working directory.
func runToolInDir(dir, name string, args ...string) ([]byte, *ToolOutcome) {
	return runToolEnv(dir, nil, toolTimeout, name, args...)
}

// runToolEnv is the single choke point for every scanner invocation: it
// resolves the binary, enforces the timeout, captures combined stderr/stdout
// and classifies the outcome. `env` holds extra KEY=VALUE pairs for the child
// process (e.g. SEMGREP_SEND_METRICS=off, TRIVY_CACHE_DIR=...).
func runToolEnv(dir string, env []string, timeout time.Duration, name string, args ...string) ([]byte, *ToolOutcome) {
	outcome := &ToolOutcome{Tool: name}
	start := time.Now()
	defer func() { outcome.Duration = time.Since(start) }()

	bin := findTool(name)
	if bin == "" {
		outcome.Status = statusMissing
		outcome.Error = name + " is not installed (checked SAST_TOOLS_DIR, /opt/bin, /usr/local/bin and PATH)"
		log.Printf("[sast] %s: %s", name, outcome.Error)
		return nil, outcome
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	outcome.ExitCode = exitCode(err)

	switch {
	case ctx.Err() != nil:
		outcome.Status = statusTimeout
		outcome.Error = "timed out after " + timeout.String()
		log.Printf("[sast] %s: %s", name, outcome.Error)
		return nil, outcome
	case err != nil && len(out) == 0:
		outcome.Status = statusError
		outcome.Error = err.Error()
		log.Printf("[sast] %s: failed: %v", name, err)
		return nil, outcome
	case err != nil:
		// Non-zero exit with output. For finding-orientated tools this is the
		// designed "found issues" signal (semgrep exits 1, gitleaks exits 1,
		// trivy only with --exit-code). The caller decides what the output is.
		outcome.Status = statusSuccess
		log.Printf("[sast] %s: exited with code %d but produced output; treating output as the report", name, outcome.ExitCode)
	default:
		outcome.Status = statusSuccess
	}
	return out, outcome
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// ToolStatusCollector gathers per-tool outcomes so the report can surface
// scanners that could not run instead of silently treating them as clean.
// It is safe for concurrent use by the analyzer's goroutines.
type ToolStatusCollector struct {
	mu       sync.Mutex
	statuses []models.ToolStatus
}

// Record appends a tool outcome to the scan's status list.
func (c *ToolStatusCollector) Record(o *ToolOutcome) {
	if c == nil || o == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statuses = append(c.statuses, models.ToolStatus{
		Tool:            o.Tool,
		Status:          o.Status,
		Error:           o.Error,
		DurationSeconds: o.Duration.Seconds(),
		Findings:        o.Findings,
	})
}

// Snapshot returns a copy of every recorded status, safe to attach to the
// result while goroutines may still be running.
func (c *ToolStatusCollector) Snapshot() []models.ToolStatus {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]models.ToolStatus, len(c.statuses))
	copy(out, c.statuses)
	return out
}

// relPath converts a tool-reported file path into one relative to the project
// root, so findings are portable and never leak the server's temp-directory
// layout (e.g. "/tmp/blackhat-projects/project_123/src/app.py" -> "src/app.py").
// Already-relative paths (gosec reports "./pkg/x.go", gitleaks "src/app.py")
// are cleaned and returned unchanged. Paths that cannot be made relative (or
// that point outside the project) are returned as-is.
func relPath(projectPath, p string) string {
	if p == "" {
		return p
	}
	if !filepath.IsAbs(p) {
		// Already-relative path (gosec reports "./pkg/x.go", gitleaks
		// "src/app.py"): normalize separators. filepath.Clean strips any
		// leading "./" so the result is a plain project-relative path.
		return filepath.ToSlash(filepath.Clean(p))
	}
	rel, err := filepath.Rel(projectPath, p)
	if err != nil {
		return p
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return p
	}
	return rel
}

// normalizeSeverity maps the many severity vocabularies used by the different
// tools onto the single schema the frontend expects: critical|high|medium|low.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "error":
		return "critical"
	case "high", "warning":
		return "high"
	case "medium", "warn", "info", "note":
		return "medium"
	case "low":
		return "low"
	default:
		return "low"
	}
}

// readFileContent reads a file (replaces the old exec-based helper so it works
// on every OS, including Windows dev machines).
func readFileContent(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// extractJSONValue returns the string value of the first occurrence of `key`
// in a JSON fragment. Used by the language-specific quality runners that keep
// lightweight parsing. It only handles quoted string values.
func extractJSONValue(json, key string) string {
	searchKey := "\"" + key + "\":"
	idx := strings.Index(json, searchKey)
	if idx == -1 {
		return ""
	}
	rest := json[idx+len(searchKey):]
	rest = strings.TrimSpace(rest)
	if len(rest) < 2 {
		return ""
	}
	if rest[0] == '"' {
		endIdx := strings.Index(rest[1:], "\"")
		if endIdx == -1 {
			return ""
		}
		return rest[1 : endIdx+1]
	}
	return ""
}

// truncate limits a string to n characters for safe embedding in error/status
// messages (e.g. a snippet of a scanner's stderr so failures are diagnosable).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "…"
}

// trivyCacheDir returns where Trivy should keep its vulnerability DB and
// scan cache: the TRIVY_CACHE_DIR env var when set, otherwise /opt/trivy-cache
// (the Docker volume), otherwise a subdir of the OS temp dir. An empty string
// means "let trivy use its default".
func trivyCacheDir() string {
	if d := os.Getenv("TRIVY_CACHE_DIR"); d != "" {
		return d
	}
	for _, d := range []string{"/opt/trivy-cache", filepath.Join(os.TempDir(), "trivy-cache")} {
		if err := os.MkdirAll(d, 0o755); err == nil {
			return d
		}
	}
	return ""
}
