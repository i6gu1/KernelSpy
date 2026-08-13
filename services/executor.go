package services

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"
)

// Execution backend modes (values of the SAST_EXECUTOR env var).
const (
	executorModeNative = "native"
	executorModeDocker = "docker"
)

// ExecOptions describes a single scanner invocation in an executor-agnostic
// way. Runners build these through runTool / runToolInDir / runToolEnv; the
// active Executor decides how the tool is actually launched (host binary vs.
// container image).
type ExecOptions struct {
	Tool    string
	Args    []string
	WorkDir string
	Env     []string
	Timeout time.Duration
}

// Executor is the pluggable back-end that launches a scanner CLI. This is the
// seam that lets the same runner code execute tools natively OR inside Docker
// containers without any per-runner knowledge of the execution model.
//
//   - NativeExecutor runs binaries installed into the image by build.sh
//     (the default; the only option on serverless runtimes like Vercel,
//     where no Docker daemon exists).
//   - DockerExecutor runs each tool inside its official container image with
//     the project mounted READ-ONLY. Enabled with SAST_EXECUTOR=docker on a
//     host with a working Docker daemon; tools without an image mapping fall
//     back to the native install.
type Executor interface {
	Invoke(opts ExecOptions) ([]byte, *ToolOutcome)
}

// ---- executor selection ----

var (
	execOnce   sync.Once
	activeExec Executor
	execMode   = executorModeNative
)

// dockerDaemonProbe is a variable so tests can stub it; it reports whether a
// Docker CLI and a reachable daemon are present.
var dockerDaemonProbe = dockerDaemonAvailable

// getExecutor returns the active execution backend, resolved once from the
// SAST_EXECUTOR env var (default: native). Docker mode is only used when a
// Docker CLI + reachable daemon exist; otherwise the executor silently falls
// back to native so the pipeline keeps working on any host.
func getExecutor() Executor {
	execOnce.Do(func() {
		switch os.Getenv("SAST_EXECUTOR") {
		case "docker":
			if dockerDaemonProbe() {
				activeExec = DockerExecutor{}
				execMode = executorModeDocker
				log.Printf("[executor] SAST_EXECUTOR=docker: running scanners in their official container images")
			} else {
				activeExec = NativeExecutor{}
				execMode = executorModeNative
				log.Printf("[executor] SAST_EXECUTOR=docker but no Docker daemon is reachable — falling back to native execution")
			}
		default:
			activeExec = NativeExecutor{}
			execMode = executorModeNative
		}
	})
	return activeExec
}

// getExecutorMode returns "native" or "docker" after resolving the executor.
func getExecutorMode() string {
	getExecutor()
	return execMode
}

// toolAvailable reports whether a scanner can run under the active executor:
// native mode requires the binary (via findTool); docker mode additionally
// accepts any tool that has an image mapping (it runs in a container even if
// no native binary exists).
func toolAvailable(name string) bool {
	getExecutor()
	if execMode == executorModeDocker {
		if _, ok := dockerToolSpecs[name]; ok {
			return true
		}
	}
	return findTool(name) != ""
}

// resetExecutor clears the cached executor so tests (and configuration
// reloads) can re-resolve SAST_EXECUTOR.
func resetExecutor() {
	execOnce = sync.Once{}
	activeExec = nil
	execMode = executorModeNative
}

// dockerDaemonAvailable reports whether the docker CLI exists and the daemon
// responds (bounded by a short timeout so a dead socket can never stall the
// pipeline).
func dockerDaemonAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

// ---- native executor ----

// NativeExecutor launches scanners as host processes, using the binaries
// installed by build.sh (discovered via findTool). It preserves the original
// pipeline behavior exactly: per-tool timeout via context, combined-output
// capture, and the missing/timeout/error/success outcome classification.
type NativeExecutor struct{}

func (NativeExecutor) Invoke(opts ExecOptions) ([]byte, *ToolOutcome) {
	outcome := &ToolOutcome{Tool: opts.Tool}
	start := time.Now()
	defer func() { outcome.Duration = time.Since(start) }()

	bin := findTool(opts.Tool)
	if bin == "" {
		outcome.Status = statusMissing
		outcome.Error = opts.Tool + " is not installed (checked SAST_TOOLS_DIR, /opt/bin, /usr/local/bin and PATH)"
		log.Printf("[sast] %s: %s", opts.Tool, outcome.Error)
		return nil, outcome
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, opts.Args...)
	cmd.Dir = opts.WorkDir
	cmd.Env = append(os.Environ(), opts.Env...)
	out, err := cmd.CombinedOutput()
	outcome.ExitCode = exitCode(err)

	switch {
	case ctx.Err() != nil:
		outcome.Status = statusTimeout
		outcome.Error = "timed out after " + opts.Timeout.String()
		log.Printf("[sast] %s: %s", opts.Tool, outcome.Error)
		return nil, outcome
	case err != nil && len(out) == 0:
		outcome.Status = statusError
		outcome.Error = err.Error()
		log.Printf("[sast] %s: failed: %v", opts.Tool, err)
		return nil, outcome
	case err != nil:
		// Non-zero exit with output: the designed "found issues" signal for
		// finding-oriented tools (semgrep exits 1, gitleaks exits 1, trivy
		// only with --exit-code). The caller decides what the output is.
		outcome.Status = statusSuccess
		log.Printf("[sast] %s: exited with code %d but produced output; treating output as the report", opts.Tool, outcome.ExitCode)
	default:
		outcome.Status = statusSuccess
	}
	return out, outcome
}

// ---- docker executor ----

// dockerToolSpec pins a scanner to the container image it runs in. Tools
// without an entry in dockerToolSpecs fall back to the native install — this
// keeps the heavy scanners (CodeQL, Dependency-Check, SpotBugs) working
// unchanged, since build.sh already installs them into the image on Docker
// hosts and they have no small official container image.
type dockerToolSpec struct {
	image string
	// entry optionally wraps the image command — used by eslint, which has no
	// official image and bootstraps the security plugins with npm inside the
	// container before running.
	entry []string
	// cacheEnv names a host-path env var that is remapped to /cache inside
	// the container AND bind-mounted, so feeds (trivy's vulnerability DB)
	// survive across runs.
	cacheEnv string
}

// dockerToolSpecs is the containerized polyglot execution matrix: scanner ->
// official (or community-maintained) image.
//
// cppcheck deliberately has NO entry: no maintained public image exists, so
// the executor falls back to the native install (the same path CodeQL,
// Dependency-Check and SpotBugs take) — on Docker hosts build.sh installs it
// via apt into the image.
var dockerToolSpecs = map[string]dockerToolSpec{
	"semgrep":  {image: "returntocorp/semgrep:latest"},
	"bandit":   {image: "ghcr.io/pycontribs/bandit:latest"},
	"gosec":    {image: "securego/gosec:latest"},
	"gitleaks": {image: "ghcr.io/gitleaks/gitleaks:latest"},
	"trivy":    {image: "aquasec/trivy:latest", cacheEnv: "TRIVY_CACHE_DIR"},
	"njsscan":  {image: "opensecurity/njsscan:latest"},
	"eslint": {
		image: "node:20-bookworm-slim",
		entry: []string{
			"sh", "-c",
			"npm install -g --silent eslint@8 eslint-plugin-security eslint-plugin-no-secrets >/dev/null 2>&1 || true; exec eslint \"$@\"",
			"sh",
		},
	},
	"shellcheck": {image: "koalaman/shellcheck-alpine:latest"},
	"brakeman":   {image: "presidentbeef/brakeman:latest"},
	"checkov":    {image: "bridgecrew/checkov:latest"},
}

// DockerExecutor runs each scanner in its official container image with strict
// isolation:
//
//   - the project directory is bind-mounted READ-ONLY at /scan, so a scanner
//     can never mutate the analyzed code (maximum isolation);
//   - the host temp dir is mounted writable at /tmp so tools that write
//     report files (gitleaks --report-path, ...) keep working unchanged;
//   - trivy's TRIVY_CACHE_DIR is remapped to a persistent /cache mount;
//   - every invocation is bounded by the same per-tool timeout as native mode
//     and classified into the same outcome vocabulary.
//
// Arguments that reference the mounted project or the host temp dir are
// translated to their container paths automatically.
type DockerExecutor struct{}

func (DockerExecutor) Invoke(opts ExecOptions) ([]byte, *ToolOutcome) {
	spec, ok := dockerToolSpecs[opts.Tool]
	if !ok {
		// No container image for this tool — run the native install instead.
		return (NativeExecutor{}).Invoke(opts)
	}

	outcome := &ToolOutcome{Tool: opts.Tool}
	start := time.Now()
	defer func() { outcome.Duration = time.Since(start) }()

	mount := dockerMountDir(opts)
	if mount == "" {
		outcome.Status = statusError
		outcome.Error = opts.Tool + ": cannot run in docker mode — no project path to mount (pass the project dir as the work dir or an argument)"
		log.Printf("[executor] %s", outcome.Error)
		return nil, outcome
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	args := []string{"run", "--rm"}
	args = append(args, "-v", mount+":/scan:ro")    // read-only project mount
	args = append(args, "-w", "/scan")              // tools that scan "." or "./..." see the project
	args = append(args, "-v", os.TempDir()+":/tmp") // writable temp workspace for report files
	if spec.cacheEnv != "" {
		if hostCache := envValue(opts.Env, spec.cacheEnv); hostCache != "" {
			args = append(args, "-v", hostCache+":/cache") // persistent feed/cache
		}
	}
	args = append(args, spec.image)
	if len(spec.entry) > 0 {
		args = append(args, spec.entry...)
	}
	args = append(args, dockerTranslateArgs(opts, mount)...)

	bin, err := exec.LookPath("docker")
	if err != nil {
		outcome.Status = statusError
		outcome.Error = "docker binary not found"
		log.Printf("[executor] %s", outcome.Error)
		return nil, outcome
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), dockerTranslateEnv(opts.Env)...)
	out, err := cmd.CombinedOutput()
	outcome.ExitCode = exitCode(err)

	switch {
	case ctx.Err() != nil:
		outcome.Status = statusTimeout
		outcome.Error = "timed out after " + opts.Timeout.String()
		log.Printf("[executor] docker %s: %s", opts.Tool, outcome.Error)
		return nil, outcome
	case err != nil && len(out) == 0:
		outcome.Status = statusError
		outcome.Error = err.Error()
		log.Printf("[executor] docker %s: failed: %v", opts.Tool, err)
		return nil, outcome
	case err != nil:
		outcome.Status = statusSuccess
		log.Printf("[executor] docker %s: exited with code %d but produced output; treating output as the report", opts.Tool, outcome.ExitCode)
	default:
		outcome.Status = statusSuccess
	}
	return out, outcome
}

// dockerMountDir resolves the host directory that must be mounted read-only
// into the container. It prefers the runner's work dir (gosec, eslint), then
// explicit source flags (--source / --scan / --source-root=...), then the
// trailing absolute project path (semgrep, bandit, trivy, njsscan). Host temp
// paths are never chosen as the mount root.
func dockerMountDir(opts ExecOptions) string {
	if opts.WorkDir != "" {
		return opts.WorkDir
	}
	for i := 0; i < len(opts.Args); i++ {
		a := opts.Args[i]
		for _, prefix := range []string{"--source-root=", "--scan=", "--source="} {
			if strings.HasPrefix(a, prefix) {
				v := strings.TrimPrefix(a, prefix)
				if isAbsHost(v) {
					return v
				}
			}
		}
		switch a {
		case "--source", "--scan", "--source-root":
			if i+1 < len(opts.Args) && isAbsHost(opts.Args[i+1]) {
				return opts.Args[i+1]
			}
		}
	}
	for i := len(opts.Args) - 1; i >= 0; i-- {
		a := opts.Args[i]
		if !isAbsHost(a) {
			continue
		}
		// The scan root lives under the host temp dir on Linux
		// (/tmp/blackhat-projects/…), so a temp path is the project only when
		// it is a directory — plain files under temp are report outputs
		// (gitleaks --report-path, …) and must never be mounted as /scan.
		if underDir(a, os.TempDir()) {
			if info, err := os.Stat(a); err != nil || !info.IsDir() {
				continue
			}
		}
		return a
	}
	return ""
}

// dockerTranslateArgs maps every absolute host path in the invocation onto its
// container path.
func dockerTranslateArgs(opts ExecOptions, mount string) []string {
	out := make([]string, 0, len(opts.Args))
	for _, a := range opts.Args {
		out = append(out, dockerTranslatePath(a, mount))
	}
	return out
}

// dockerTranslatePath rewrites absolute host paths in a single argument so
// they resolve inside the container: the project mount becomes /scan and the
// host temp dir becomes /tmp. Handles bare paths and --flag=/path forms.
func dockerTranslatePath(arg, mount string) string {
	if i := strings.Index(arg, "="); i > 0 {
		key, val := arg[:i+1], arg[i+1:]
		if !isAbsHost(val) {
			return arg
		}
		if mount != "" && underDir(val, mount) {
			return key + "/scan" + strings.TrimPrefix(normalizeHost(val), normalizeHost(mount))
		}
		if underDir(val, os.TempDir()) {
			return key + "/tmp" + strings.TrimPrefix(normalizeHost(val), normalizeHost(os.TempDir()))
		}
		return arg
	}
	if !isAbsHost(arg) {
		return arg
	}
	if mount != "" && underDir(arg, mount) {
		return "/scan" + strings.TrimPrefix(normalizeHost(arg), normalizeHost(mount))
	}
	if underDir(arg, os.TempDir()) {
		return "/tmp" + strings.TrimPrefix(normalizeHost(arg), normalizeHost(os.TempDir()))
	}
	return arg
}

// dockerTranslateEnv rewrites host-path env vars for the container. Currently
// only trivy's cache dir is remapped (to the /cache mount).
func dockerTranslateEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "TRIVY_CACHE_DIR=") {
			out = append(out, "TRIVY_CACHE_DIR=/cache")
			continue
		}
		out = append(out, kv)
	}
	return out
}

// envValue returns the value of the first KEY=VALUE entry matching key.
func envValue(env []string, key string) string {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return strings.TrimPrefix(kv, prefix)
		}
	}
	return ""
}

// isAbsHost reports whether p is an absolute path in the host's syntax, on
// every OS: POSIX absolute (/opt/bin) or a Windows drive path (C:\… or C:/…).
// The container always sees POSIX paths, so this must NOT be the path package's
// POSIX-only IsAbs.
func isAbsHost(p string) bool {
	if path.IsAbs(p) {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// normalizeHost maps host path separators to POSIX (\ → /) so containment
// checks and translations behave identically on Windows and Unix hosts. The
// result is only used for comparisons and container paths — host-side mount
// sources keep their native separators.
func normalizeHost(p string) string {
	if strings.ContainsRune(p, '\\') {
		return strings.ReplaceAll(p, "\\", "/")
	}
	return p
}

// underDir reports whether p is root itself or lives under root. Both paths
// are normalized to POSIX separators first, so Windows drive paths compare
// correctly.
func underDir(p, root string) bool {
	root = path.Clean(normalizeHost(root))
	p = path.Clean(normalizeHost(p))
	if p == root {
		return true
	}
	return strings.HasPrefix(p, root) && len(p) > len(root) && p[len(root)] == '/'
}
