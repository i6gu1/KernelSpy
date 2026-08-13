package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"black-hat/models"
)

// TestShellFilesDetection verifies the shell runner only collects shell
// scripts and caps pathological projects.
func TestShellFilesDetection(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"a.sh":     "#!/bin/sh\necho hi\n",
		"sub/b.sh": "#!/bin/bash\nls\n",
		"c.js":     "console.log(1);",
		"d.txt":    "plain",
	} {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}

	files := shellFiles(dir)
	if len(files) != 2 {
		t.Fatalf("expected 2 shell files, got %d (%v)", len(files), files)
	}
	for _, f := range files {
		if !strings.HasSuffix(f, ".sh") {
			t.Errorf("unexpected file collected: %s", f)
		}
	}
}

// TestShellCheckSkipsShellFreeProjects verifies a project without shell
// scripts records a clean "skipped" status instead of running the tool.
func TestShellCheckSkipsShellFreeProjects(t *testing.T) {
	dir := writeProject(t, map[string]string{"app.js": "console.log(1);"})
	statuses := &ToolStatusCollector{}
	findings, _ := NewShellCheckRunner().Run(dir, statuses)

	if len(findings) != 0 {
		t.Fatalf("expected no findings on a shell-free project, got %d", len(findings))
	}
	got := statusFor(statuses, "shellcheck")
	if got == nil || got.Status != statusSkipped {
		t.Fatalf("expected skipped status, got %+v", got)
	}
}

// TestContainsIaCDetection verifies Checkov's gate fires on Terraform,
// Dockerfile and docker-compose but not on generic source/config projects.
func TestContainsIaCDetection(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"terraform", map[string]string{"main.tf": "resource \"x\" {}"}, true},
		{"dockerfile", map[string]string{"Dockerfile": "FROM debian"}, true},
		{"compose", map[string]string{"docker-compose.yml": "services:\n  web:\n"}, true},
		{"k8s manifest", map[string]string{"k8s/deployment.yaml": "apiVersion: apps/v1"}, true},
		{"plain yaml", map[string]string{"config.yaml": "a: 1"}, false},
		{"plain source", map[string]string{"app.go": "package main"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeProject(t, c.files)
			if got := containsIaCFiles(dir); got != c.want {
				t.Fatalf("containsIaCFiles = %v, want %v", got, c.want)
			}
		})
	}
}

// TestCheckovSkipsNonIaCProjects verifies the runner records skipped without
// invoking the tool when no IaC is present.
func TestCheckovSkipsNonIaCProjects(t *testing.T) {
	dir := writeProject(t, map[string]string{"app.py": "print('hi')"})
	statuses := &ToolStatusCollector{}
	findings := NewCheckovRunner().Run(dir, statuses)

	if len(findings) != 0 {
		t.Fatalf("expected no findings on a non-IaC project, got %d", len(findings))
	}
	got := statusFor(statuses, "checkov")
	if got == nil || got.Status != statusSkipped {
		t.Fatalf("expected skipped status, got %+v", got)
	}
}

// TestIsRailsApp verifies Brakeman's gate accepts Rails apps and rejects
// plain Ruby scripts.
func TestIsRailsApp(t *testing.T) {
	rails := writeProject(t, map[string]string{
		"Gemfile": "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n",
	})
	if !isRailsApp(rails) {
		t.Fatal("expected Gemfile-with-rails project to look like a Rails app")
	}

	appTree := writeProject(t, map[string]string{"app/controllers/x.rb": "class X; end"})
	if !isRailsApp(appTree) {
		t.Fatal("expected app/ tree to look like a Rails app")
	}

	plain := writeProject(t, map[string]string{"script.rb": "puts 'hi'"})
	if isRailsApp(plain) {
		t.Fatal("expected a plain ruby script NOT to look like a Rails app")
	}
}

// TestBrakemanSkipsNonRailsProjects verifies the runner records skipped for
// plain Ruby without invoking the tool.
func TestBrakemanSkipsNonRailsProjects(t *testing.T) {
	dir := writeProject(t, map[string]string{"script.rb": "puts ARGV.join(' ')"})
	statuses := &ToolStatusCollector{}
	findings := NewBrakemanRunner().Run(dir, statuses)

	if len(findings) != 0 {
		t.Fatalf("expected no findings on a non-Rails project, got %d", len(findings))
	}
	got := statusFor(statuses, "brakeman")
	if got == nil || got.Status != statusSkipped {
		t.Fatalf("expected skipped status, got %+v", got)
	}
}

// TestCppcheckNotRunWithoutCLanguages verifies the analyzer does not even
// attempt cppcheck on a project with no C/C++ sources.
func TestCppcheckNotRunWithoutCLanguages(t *testing.T) {
	res := runBuiltin(t, map[string]string{"app.py": "print('hi')"})
	for _, st := range res.ToolStatuses {
		if st.Tool == "cppcheck" {
			t.Fatalf("cppcheck should not be dispatched without C/C++ files: %+v", st)
		}
	}
}

// statusFor finds a recorded tool status by tool name.
func statusFor(statuses *ToolStatusCollector, tool string) *models.ToolStatus {
	for _, st := range statuses.Snapshot() {
		if st.Tool == tool {
			return &st
		}
	}
	return nil
}
