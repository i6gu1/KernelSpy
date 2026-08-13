package services

import (
	"os"
	"path"
	"path/filepath"
	"testing"
)

// TestExecutorDefaultsToNative verifies the default executor is native
// (backward compatible — no SAST_EXECUTOR set).
func TestExecutorDefaultsToNative(t *testing.T) {
	t.Setenv("SAST_EXECUTOR", "")
	resetExecutor()
	defer resetExecutor()

	if got := getExecutorMode(); got != executorModeNative {
		t.Fatalf("expected native executor by default, got %q", got)
	}
	if _, ok := getExecutor().(NativeExecutor); !ok {
		t.Fatal("expected a NativeExecutor")
	}
}

// TestExecutorDockerWithDaemon verifies SAST_EXECUTOR=docker selects the
// Docker executor when a daemon is reachable, and falls back to native when
// the daemon probe fails.
func TestExecutorDockerWithDaemon(t *testing.T) {
	oldProbe := dockerDaemonProbe
	defer func() { dockerDaemonProbe = oldProbe }()

	t.Setenv("SAST_EXECUTOR", "docker")
	resetExecutor()
	defer resetExecutor()

	dockerDaemonProbe = func() bool { return true }
	resetExecutor()
	if got := getExecutorMode(); got != executorModeDocker {
		t.Fatalf("expected docker executor with reachable daemon, got %q", got)
	}

	dockerDaemonProbe = func() bool { return false }
	resetExecutor()
	if got := getExecutorMode(); got != executorModeNative {
		t.Fatalf("expected native fallback when daemon unreachable, got %q", got)
	}
}

// TestDockerMountDir verifies mount-root resolution across the invocation
// styles the runners actually use. The project dir is created on disk because
// dockerMountDir requires a path under the host temp dir to be a real
// directory (report *files* under temp must never be mounted as /scan).
func TestDockerMountDir(t *testing.T) {
	// Put the fake project under os.TempDir() on purpose: on Linux the real
	// project dir lives in /tmp (os.TempDir()), and the mount resolver must
	// accept a directory under temp while rejecting report files there.
	proj := filepath.Join(os.TempDir(), "blackhat-projects", "project_1")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	// WorkDir (gosec, eslint).
	if got := dockerMountDir(ExecOptions{WorkDir: proj}); got != proj {
		t.Errorf("WorkDir mount = %q, want %q", got, proj)
	}

	// Trailing absolute project path (semgrep, bandit, trivy, njsscan).
	opts := ExecOptions{Args: []string{"--json", "x.go", proj}}
	if got := dockerMountDir(opts); got != proj {
		t.Errorf("trailing-path mount = %q, want %q", got, proj)
	}

	// --source <proj> (gitleaks) must win over the trailing temp report path.
	report := filepath.Join(os.TempDir(), "gitleaks-report-1.json")
	if err := os.WriteFile(report, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts = ExecOptions{Args: []string{"detect", "--source", proj, "--report-path", report}}
	if got := dockerMountDir(opts); got != proj {
		t.Errorf("--source mount = %q, want %q", got, proj)
	}

	// --source-root=<proj> (codeql-style flags).
	opts = ExecOptions{Args: []string{"database", "create", "--source-root=" + proj, "/tmp/db"}}
	if got := dockerMountDir(opts); got != proj {
		t.Errorf("--source-root= mount = %q, want %q", got, proj)
	}

	// A trailing report file under temp alone is NOT a mount root.
	opts = ExecOptions{Args: []string{"detect", "--report-path", report}}
	if got := dockerMountDir(opts); got != "" {
		t.Errorf("expected empty mount for a trailing report file, got %q", got)
	}

	// Nothing mountable -> "".
	if got := dockerMountDir(ExecOptions{Args: []string{"--version"}}); got != "" {
		t.Errorf("expected empty mount for version probe, got %q", got)
	}
}

// TestDockerTranslatePath verifies host -> container path rewriting for the
// project mount and the host temp dir, in bare and --flag= forms.
func TestDockerTranslatePath(t *testing.T) {
	mount := "/tmp/blackhat-projects/project_1"
	tmp := os.TempDir()

	cases := []struct {
		in, want string
	}{
		{in: mount, want: "/scan"},
		{in: mount + "/src/app.py", want: "/scan/src/app.py"},
		{in: "--source=" + mount, want: "--source=/scan"},
		{in: "--source-root=" + mount + "/pom.xml", want: "--source-root=/scan/pom.xml"},
		{in: "--report-path=" + tmp + "/gitleaks.json", want: "--report-path=/tmp/gitleaks.json"},
		{in: "--format=json", want: "--format=json"},
		{in: "relative/path.go", want: "relative/path.go"},
	}
	for _, c := range cases {
		if got := dockerTranslatePath(c.in, mount); got != c.want {
			t.Errorf("dockerTranslatePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestDockerTranslateEnv verifies trivy's cache dir is remapped to /cache.
func TestDockerTranslateEnv(t *testing.T) {
	env := []string{"TRIVY_CACHE_DIR=/opt/trivy-cache", "SEMGREP_SEND_METRICS=off"}
	got := dockerTranslateEnv(env)
	want := []string{"TRIVY_CACHE_DIR=/cache", "SEMGREP_SEND_METRICS=off"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("dockerTranslateEnv = %v, want %v", got, want)
	}
}

// TestToolAvailableDockerMode verifies that in docker mode a tool with an
// image mapping is "available" even when no native binary exists, while tools
// without a mapping fall back to the native check.
func TestToolAvailableDockerMode(t *testing.T) {
	oldProbe := dockerDaemonProbe
	defer func() { dockerDaemonProbe = oldProbe }()

	t.Setenv("SAST_EXECUTOR", "docker")
	dockerDaemonProbe = func() bool { return true }
	resetExecutor()
	defer resetExecutor()

	if !toolAvailable("semgrep") {
		t.Error("semgrep has an image mapping and must be available in docker mode")
	}
	// A tool with no docker spec falls back to the native check; a name that
	// is guaranteed to have no binary reports missing.
	if toolAvailable("definitely-no-such-scanner-binary-xyz") {
		t.Error("tool without image mapping and without a native binary must report missing")
	}
}

// TestSnippetAt verifies the vulnerable-code-snippet extraction.
func TestSnippetAt(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", "import sqlite3\n\ndef get_user(name):\n    return sqlite3.connect('db').execute('SELECT * FROM users WHERE name = \"' + name + '\"')\n")

	// Exact vulnerable line, trimmed.
	snippet := snippetAt(dir, "app.py", 4)
	want := "return sqlite3.connect('db').execute('SELECT * FROM users WHERE name = \"' + name + '\"')"
	if snippet != want {
		t.Errorf("snippetAt = %q, want %q", snippet, want)
	}

	// Line out of range -> "".
	if got := snippetAt(dir, "app.py", 999); got != "" {
		t.Errorf("snippetAt(out of range) = %q, want empty", got)
	}
	// Missing file -> "".
	if got := snippetAt(dir, "nope.py", 1); got != "" {
		t.Errorf("snippetAt(missing file) = %q, want empty", got)
	}
	// Snippet capped at 200 chars.
	content := ""
	for i := 0; i < 40; i++ {
		content += "fmt.Println(\"a very long line of code to force truncation of the snippet\") // "
	}
	writeFile(t, dir, "long.go", content)
	if got := snippetAt(dir, "long.go", 1); len(got) > 200 {
		t.Errorf("snippetAt capped length = %d, want <= 200", len(got))
	}

	// Path-traversal guard: a tool-reported path must never escape the
	// project root (a hostile scanner must not read host files into reports).
	outside := filepath.Join(dir, "..", "outside-secret.txt")
	if err := os.WriteFile(outside, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := snippetAt(dir, "../outside-secret.txt", 1); got != "" {
		t.Errorf("snippetAt must reject paths escaping the project root, got %q", got)
	}
}

// TestUnderDir sanity-checks the path containment helper.
func TestUnderDir(t *testing.T) {
	cases := []struct {
		p, root string
		want    bool
	}{
		{"/tmp/proj", "/tmp/proj", true},
		{"/tmp/proj/src", "/tmp/proj", true},
		{"/tmp/proj2", "/tmp/proj", false},
		{"/etc", "/tmp/proj", false},
		{path.Clean(os.TempDir()) + "/x", os.TempDir(), true},
	}
	for _, c := range cases {
		if got := underDir(c.p, c.root); got != c.want {
			t.Errorf("underDir(%q, %q) = %v, want %v", c.p, c.root, got, c.want)
		}
	}
}
