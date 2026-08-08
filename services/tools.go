package services

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// toolTimeout bounds every SAST tool invocation so a hung scanner can never
// stall the pipeline forever.
const toolTimeout = 120 * time.Second

// findTool locates a SAST binary. It checks, in order:
//  1. the SAST_TOOLS_DIR environment variable (custom install path)
//  2. /opt/bin (the directory build.sh installs tools into for Vercel/Docker)
//  3. /usr/local/bin
//  4. the PATH
//
// Returning "" means the tool is not installed; runners then report no
// findings instead of failing the whole pipeline.
func findTool(name string) string {
	var candidates []string

	if dir := os.Getenv("SAST_TOOLS_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, name))
	}
	if runtime.GOOS != "windows" {
		candidates = append(candidates,
			filepath.Join("/opt/bin", name),
			filepath.Join("/usr/local/bin", name),
		)
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

// runTool runs a discovered tool and returns its combined output. It returns
// (nil, false) when the binary is missing or the command fails, so callers can
// treat unavailable tools as "no findings" without breaking the scan.
func runTool(name string, args ...string) ([]byte, bool) {
	return runToolInDir("", name, args...)
}

// runToolInDir runs a tool with the given working directory (used by tools
// like gosec/golangci-lint that need a module context). An empty dir is
// equivalent to the process working directory.
func runToolInDir(dir, name string, args ...string) ([]byte, bool) {
	bin := findTool(name)
	if bin == "" {
		log.Printf("[sast] tool %q not found, skipping", name)
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			log.Printf("[sast] tool %q timed out", name)
			return nil, false
		}
		if len(out) == 0 {
			log.Printf("[sast] tool %q failed: %v", name, err)
			return nil, false
		}
	}
	return out, true
}

// normalizeSeverity maps the many severity vocabularies used by the different
// tools onto the single schema the frontend expects: critical|high|medium|low.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "error":
		return "critical"
	case "high", "warning":
		return "high"
	case "medium", "warn", "info":
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
