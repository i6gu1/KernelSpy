package services

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectLanguagesHTMLJS ensures an HTML/JS project is never mislabeled
// as Python.
func TestDetectLanguagesHTMLJS(t *testing.T) {
	dir, err := os.MkdirTemp("", "ltdebug")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	for name, content := range map[string]string{
		"index.html":  "<!DOCTYPE html><html><body><h1>Hi</h1></body></html>",
		"app.js":      "const u = new URLSearchParams(window.location.search);",
		"server.js":   "const express=require('express');app.listen(3000);",
		"package.json": `{ "name": "t", "dependencies": { "express": "4.18.0" } }`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	d := NewDetector()
	langs := d.DetectLanguages(dir)
	t.Logf("DetectLanguages => %v", langs)
	for _, l := range langs {
		if l == "python" {
			t.Errorf("BUG: python detected for an HTML/JS project: %v", langs)
		}
	}
}