package services

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	// Nested fixtures (node_modules/pkg/...) need their parent dirs created;
	// os.WriteFile fails on a missing parent on every OS, Windows included.
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDetectLanguagesFromManifests proves a project is detected from its
// dependency manifests even when it ships no source files of that language
// (the classic transpiled-frontend / build-system-only case).
func TestDetectLanguagesFromManifests(t *testing.T) {
	dir := t.TempDir()
	// A Python backend described only by requirements.txt plus a package.json
	// frontend manifest — no .py or .js files at all.
	writeFile(t, dir, "requirements.txt", "flask==3.0.0\n")
	writeFile(t, dir, "package.json", `{"name": "frontend"}`)
	writeFile(t, dir, "Cargo.toml", `[package] name = "x"`)

	langs := NewDetector().DetectLanguages(dir)
	expected := []string{"javascript", "python", "rust"}
	if !reflect.DeepEqual(langs, expected) {
		t.Errorf("DetectLanguages(manifests only) = %v, want %v", langs, expected)
	}
}

// TestDetectLanguagesIncludesHTMLCSS verifies the HTML/CSS languages are
// detected so polyglot scanners cover template/style files.
func TestDetectLanguagesIncludesHTMLCSS(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<html></html>")
	writeFile(t, dir, "site.css", "body {}")

	langs := NewDetector().DetectLanguages(dir)
	got := map[string]bool{}
	for _, l := range langs {
		got[l] = true
	}
	for _, want := range []string{"html", "css"} {
		if !got[want] {
			t.Errorf("expected language %q to be detected; got %v", want, langs)
		}
	}
}

// TestDetectLanguagesFromCSProj verifies C# is detected from .csproj files.
func TestDetectLanguagesFromCSProj(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.csproj", "<Project/>")

	langs := NewDetector().DetectLanguages(dir)
	found := false
	for _, l := range langs {
		if l == "csharp" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected csharp to be detected from .csproj; got %v", langs)
	}
}

// TestDetectLanguagesSorted verifies deterministic (sorted) output.
func TestDetectLanguagesSorted(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package a\n")
	writeFile(t, dir, "b.py", "x = 1\n")
	writeFile(t, dir, "c.js", "let x = 1;\n")

	langs := NewDetector().DetectLanguages(dir)
	expected := []string{"go", "javascript", "python"}
	if !reflect.DeepEqual(langs, expected) {
		t.Errorf("DetectLanguages = %v, want sorted %v", langs, expected)
	}
}

func TestDetectEcosystems(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "go.mod", "module x\n")
	writeFile(t, dir, "pom.xml", "<project/>")
	writeFile(t, dir, "app.csproj", "<Project/>")
	writeFile(t, dir, "Gemfile", "source :rubygems\n")

	ecosystems := NewDetector().DetectEcosystems(dir)
	expected := []string{"go", "maven", "npm", "nuget", "rubygems"}
	if !reflect.DeepEqual(ecosystems, expected) {
		t.Errorf("DetectEcosystems = %v, want %v", ecosystems, expected)
	}
}

// TestDetectLanguagesSkipsVendorTrees ensures node_modules/vendor/.git are not
// counted as project languages.
func TestDetectLanguagesSkipsVendorTrees(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.go", "package app\n")
	writeFile(t, dir, filepath.Join("node_modules", "pkg", "index.js"), "let x = 1;\n")
	writeFile(t, dir, filepath.Join("vendor", "dep", "main.go"), "package dep\n")

	langs := NewDetector().DetectLanguages(dir)
	if len(langs) != 1 || langs[0] != "go" {
		t.Errorf("DetectLanguages = %v, want only [go] (vendor/node_modules must be skipped)", langs)
	}
}
