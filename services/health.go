package services

import (
	"context"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ToolInfo describes a single SAST tool from the deployment's point of view:
// whether the image ships it (Found/Path), which version binary reports, and
// whether the runtime configuration intentionally disables it (Skipped). The
// /health endpoint exposes this list so a deployment's tool inventory can be
// verified in one HTTP request instead of reading a report's Scanner Status.
type ToolInfo struct {
	Name     string `json:"name"`
	Found    bool   `json:"found"`
	Path     string `json:"path,omitempty"`
	Version  string `json:"version,omitempty"`
	Skipped  bool   `json:"skipped,omitempty"`
	SkipWhy  string `json:"skip_reason,omitempty"`
	Missing  string `json:"missing_reason,omitempty"`
}

// inspectToolDef pins one tool to its binary name and, where a scanner is
// disabled by configuration, the environment variable that disables it.
type inspectToolDef struct {
	name    string
	skipEnv string
	skipWhy string
}

// inspectTools is the canonical set the rest of the pipeline refers to. Names
// match the ToolOutcome.Tool values the runners record, so a /health inventory
// is directly comparable with a report's Scanner Status rows.
var inspectTools = []inspectToolDef{
	{name: "semgrep"},
	{name: "bandit"},
	{name: "njsscan"},
	{name: "checkov", skipEnv: "SAST_SKIP_CHECKOV", skipWhy: "disabled by SAST_SKIP_CHECKOV=1"},
	{name: "eslint"},
	{name: "shellcheck", skipEnv: "SAST_SKIP_SHELLCHECK", skipWhy: "disabled by SAST_SKIP_SHELLCHECK=1"},
	{name: "cppcheck", skipEnv: "SAST_SKIP_CPPCHECK", skipWhy: "disabled by SAST_SKIP_CPPCHECK=1"},
	{name: "brakeman", skipEnv: "SAST_SKIP_BRAKEMAN", skipWhy: "disabled by SAST_SKIP_BRAKEMAN=1"},
	{name: "spotbugs", skipEnv: "SAST_SKIP_SPOTBUGS", skipWhy: "disabled by SAST_SKIP_SPOTBUGS=1"},
	{name: "gosec"},
	{name: "gitleaks"},
	{name: "trivy"},
	{name: "codeql", skipEnv: "SAST_SKIP_CODQL", skipWhy: "disabled by SAST_SKIP_CODQL=1"},
	{name: "dependency-check", skipEnv: "SAST_SKIP_DEPCHECK", skipWhy: "disabled by SAST_SKIP_DEPCHECK=1"},
	{name: "golangci-lint"},
	{name: "clippy"},
	{name: "phpstan"},
	{name: "pmd"},
}

// InspectTools resolves the deployment's tool inventory. It never blocks on a
// slow binary long: each version probe is bounded to versionProbeTimeout, so a
// hung tool degrades to "found with no version" instead of stalling /health.
func InspectTools() []ToolInfo {
	out := make([]ToolInfo, 0, len(inspectTools))
	for _, def := range inspectTools {
		info := ToolInfo{Name: def.name}
		if def.skipEnv != "" && os.Getenv(def.skipEnv) == "1" {
			info.Skipped = true
			info.SkipWhy = def.skipWhy
			out = append(out, info)
			continue
		}
		bin := findTool(def.name)
		if bin == "" {
			info.Missing = "not installed (checked SAST_TOOLS_DIR, /opt/bin, /usr/local/bin and PATH)"
			out = append(out, info)
			continue
		}
		info.Found = true
		info.Path = bin
		info.Version = probeVersion(bin, def.name)
		out = append(out, info)
	}
	return out
}

// versionProbeTimeout bounds each --version probe so /health stays responsive
// even on a busy worker.
const versionProbeTimeout = 10 * time.Second

// probeVersion asks a discovered binary for its version without caring which
// flag style it accepts: binaries in the wild respond to --version, -version
// or a bare "version" subcommand, so try each in turn. The line chosen is the
// first one that actually looks like a version (a digit-digit pattern) so
// noisy preamble (warnings, deprecations) never masquerades as the version.
func probeVersion(bin, name string) string {
	flags := [][]string{
		{"--version"},
		{"-version"},
		{"version"},
	}
	// dependency-check needs its full tree (lib/ next to the launcher), so
	// findTool resolves it via DEPENDENCY_CHECK_HOME; the JVM startup is slow
	// and the launcher takes --version. Keep the probe generic regardless.
	for _, args := range flags {
		ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
		out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
		cancel()
		if err != nil && len(out) == 0 {
			continue
		}
		version := pickVersionLine(string(out), name)
		if version == "" {
			continue
		}
		log.Printf("[health] %s version: %s", name, version)
		return version
	}
	return ""
}

// pickVersionLine returns first line of s that contains a version-looking
// token (digits separated by dots/prefixes like v1.2). If none matches, it
// falls back to the first non-empty line so surprising tools still surface
// something readable.
func pickVersionLine(s, name string) string {
	var fallback string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if fallback == "" {
			fallback = line
		}
		if strings.Contains(name, "codeql") {
			if versionish(line) {
				return clipVersion(line)
			}
			continue
		}
		if versionish(line) {
			return clipVersion(line)
		}
	}
	return clipVersion(fallback)
}

// versionish reports whether s contains a semver-ish token such as "v0.73.0"
// or "1.9.4" — but not a bare hash or a path like "C:\scripts\str". The
// heuristic is a whitespace-adjacent digit[.]digit appears somewhere.
func versionish(s string) bool {
	re := regexp.MustCompile(`\b[vV]?[0-9]+(\.[0-9]+){1,3}\b`)
	return re.MatchString(s)
}

func clipVersion(s string) string {
	if len(s) > 160 {
		return s[:160]
	}
	return s
}