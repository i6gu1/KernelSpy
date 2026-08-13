package services

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"black-hat/models"
)

// BuiltinRunner is a zero-dependency static analyzer. It is the safety net
// that guarantees every scan produces REAL findings even when none of the
// external SAST tools (semgrep, gitleaks, trivy, bandit, ...) are installed —
// which is exactly the situation on serverless hosts like Vercel, where
// /opt/bin tools installed by build.sh are not present in the runtime
// sandbox. It performs honest pattern-based analysis (SQL injection, XSS,
// command injection, hardcoded secrets, weak crypto, unsafe deserialization,
// ...) over the uploaded source. When the full toolchain IS installed (Docker
// image), its findings simply complement the deeper tools.
//
// The analyzer is deliberately conservative: every rule requires a real
// trigger on the scanned line (e.g. a query call) combined with a
// concatenation/taint condition, so ordinary clean code is not flagged.
type BuiltinRunner struct {
	timeout     time.Duration
	maxFindings int
}

// Knobs. BUILTIN_TIMEOUT_SECONDS bounds the whole scan so the analysis always
// fits inside serverless request budgets; BUILTIN_MAX_FINDINGS caps the report
// size for pathological projects.
func NewBuiltinRunner() *BuiltinRunner {
	timeout := 45 * time.Second
	if s := os.Getenv("BUILTIN_TIMEOUT_SECONDS"); s != "" {
		if d, err := time.ParseDuration(s + "s"); err == nil {
			timeout = d
		}
	}
	maxFindings := 500
	if s := os.Getenv("BUILTIN_MAX_FINDINGS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			maxFindings = n
		}
	}
	return &BuiltinRunner{timeout: timeout, maxFindings: maxFindings}
}

const (
	builtinToolName       = "builtin"
	builtinMaxFileBytes   = 1 << 20 // skip files larger than 1 MB (minified bundles, binaries)
	builtinPerRulePerFile = 10      // cap repeated hits of one rule in one file
)

// errStopScan aborts the directory walk once the time/findings budget is gone.
var errStopScan = errors.New("builtin scan budget exhausted")

// builtinRule is one pattern rule. A line is a finding when it matches the
// trigger AND the condition AND the context, and does not match skip.
type builtinRule struct {
	id             string
	severity       string
	description    string
	recommendation string
	exts           map[string]bool // file extensions this rule applies to (nil = all text files)
	trigger        *regexp.Regexp
	condition      *regexp.Regexp
	context        *regexp.Regexp
	skip           *regexp.Regexp
}

func rule(id, sev, desc, rec string, exts map[string]bool, trigger, condition, context, skip string) builtinRule {
	r := builtinRule{
		id: id, severity: sev, description: desc, recommendation: rec, exts: exts,
		trigger: regexp.MustCompile(trigger),
	}
	if condition != "" {
		r.condition = regexp.MustCompile(condition)
	}
	if context != "" {
		r.context = regexp.MustCompile(context)
	}
	if skip != "" {
		r.skip = regexp.MustCompile(skip)
	}
	return r
}

func exts(list ...string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, e := range list {
		m[e] = true
	}
	return m
}

// Built-in rules. Severity vocabulary matches the frontend: critical|high|medium|low.
var builtinRules = []builtinRule{
	// ---------------- Python ----------------
	rule("builtin.sql-injection.python", "high",
		"SQL injection: a database query is built by concatenating values into the SQL string instead of using parameters.",
		"Use parameterized queries / prepared statements (cursor.execute(sql, params)) and never interpolate user input into SQL.",
		exts(".py"),
		`\bexecute\s*\(`,
		`(\s*[+%]\s*|f["']|\.format\s*\()`,
		`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b`, ""),
	rule("builtin.command-injection.python", "high",
		"Command injection: os.system / subprocess is invoked with shell=True or a string built by concatenation.",
		"Pass arguments as a list to subprocess without shell=True, and validate/sanitize any input that reaches a shell.",
		exts(".py"),
		`\b(os\.system|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\(`,
		`(shell\s*=\s*(True|1)|\s*[+%]\s*|f["'])`, "", ""),
	rule("builtin.unsafe-deserialization.python", "high",
		"Unsafe deserialization: pickle.loads / yaml.load can execute arbitrary code when fed untrusted data.",
		"Never deserialize untrusted data with pickle; use yaml.safe_load and validate the data source.",
		exts(".py"),
		`\b(pickle\.loads|cPickle\.loads|yaml\.load)\s*\(`,
		"", "", `(?i)Loader\s*=`),
	rule("builtin.code-execution.python", "high",
		"Arbitrary code execution: eval/exec is applied to data that may originate from user input or file contents.",
		"Avoid eval/exec entirely; if unavoidable, never evaluate untrusted input.",
		exts(".py"),
		`\b(eval|exec)\s*\(`,
		`(\$|input\s*\(|open\s*\(|sys\.argv|os\.environ|request)`, "", ""),
	rule("builtin.weak-crypto.python", "medium",
		"Weak cryptography: MD5/SHA-1/DES are cryptographically broken and must not be used for security purposes.",
		"Use a strong algorithm from the hashlib/ cryptography modules (SHA-256+, AES-GCM, Argon2 for passwords).",
		exts(".py"),
		`(?i)\b(hashlib\.)?(md5|sha1)\s*\(|\bDES\b`, "", "", ""),
	rule("builtin.ssl-no-verify.python", "medium",
		"TLS verification is disabled, allowing man-in-the-middle attacks on the connection.",
		"Remove verify=False / unverified SSL contexts so certificates are validated.",
		exts(".py"),
		`(?i)verify\s*=\s*False|ssl\._create_unverified_context`, "", "", ""),

	// ---------------- JavaScript / TypeScript ----------------
	rule("builtin.xss.javascript", "high",
		"Cross-site scripting: unsanitized data is written into the DOM via an HTML sink (innerHTML/document.write).",
		"Use textContent instead of innerHTML, or sanitize the value before insertion; escape user input.",
		exts(".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"),
		`(\.innerHTML\s*[=+]|\.outerHTML\s*[=+]|document\.write\s*\(|insertAdjacentHTML\s*\(|dangerouslySetInnerHTML)`,
		"", "", ""),
	rule("builtin.code-execution.javascript", "high",
		"Arbitrary code execution: eval / new Function executes a string that may contain untrusted data.",
		"Avoid eval and new Function; use JSON.parse for data and safe alternatives for dynamic behavior.",
		exts(".js", ".jsx", ".ts", ".tsx"),
		`\b(eval|new Function)\s*\(`,
		"", "", ""),
	rule("builtin.code-execution.javascript.timer", "medium",
		"Code execution risk: setTimeout/setInterval receives a string argument, which is evaluated as code.",
		"Pass a function reference to setTimeout/setInterval instead of a string.",
		exts(".js", ".jsx", ".ts", ".tsx"),
		`\b(setTimeout|setInterval)\s*\(\s*["'`+"`"+`]`,
		"", "", ""),
	rule("builtin.sql-injection.javascript", "high",
		"SQL injection: a database query is built by string concatenation / template literals instead of parameters.",
		"Use parameterized queries or an ORM's bound parameters; never interpolate input into SQL text.",
		exts(".js", ".jsx", ".ts", ".tsx"),
		`\.(query|execute)\s*\(`,
		`(\+\s*["'`+"`"+`]|["'`+"`"+`]\s*\+|\.concat\s*\(|`+"`"+`[^`+"`"+`]*\$\{)`,
		`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b`, ""),
	// NOTE: this rule is special-cased in scanFile so the `const cp =
	// require('child_process')` alias pattern is honored (see reRequireChildProcess).
	rule("builtin.command-injection.javascript", "high",
		"Command injection: child_process is invoked with shell:true or a command string built by concatenation.",
		"Pass arguments as an array without shell:true; avoid concatenating input into shell commands.",
		exts(".js", ".jsx", ".ts", ".tsx"),
		`\.(exec|execSync|spawn|spawnSync)\s*\(`,
		`(shell\s*:\s*(true|1)|\+\s*["'`+"`"+`]|["'`+"`"+`]\s*\+|\.concat\s*\()`, "", ""),

	// ---------------- PHP ----------------
	rule("builtin.sql-injection.php", "high",
		"SQL injection: a query is built by concatenating request data into the SQL string.",
		"Use prepared statements with bound parameters (PDO / mysqli prepared queries); never concatenate input into SQL.",
		exts(".php"),
		`\b(mysqli_query|mysql_query|pg_query|sqlsrv_query|->query|->exec)\s*\(`,
		`(\$_(GET|POST|REQUEST|COOKIE)|\s\.\s*\$|"\s*\.\s*)`,
		`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b`, ""),
	rule("builtin.command-injection.php", "high",
		"Command injection: request data reaches system/exec/shell_exec.",
		"Never pass user input to shell functions; use escapeshellarg/escapeshellcmd or avoid shell execution.",
		exts(".php"),
		`\b(system|shell_exec|passthru|proc_open|popen|exec)\s*\(`,
		`(\$_(GET|POST|REQUEST|COOKIE)|\s\.\s*\$|"\s*\.\s*\$|\s\.\s*\$_)`, "", ""),
	rule("builtin.xss.php", "high",
		"Cross-site scripting: request data is echoed directly into the HTML response unescaped.",
		"Escape all output with htmlspecialchars($value, ENT_QUOTES) or use a templating engine that auto-escapes.",
		exts(".php"),
		`(\b(echo|print)\s+\$_|<\?=\s*\$_)`,
		"", "", ""),
	rule("builtin.file-inclusion.php", "high",
		"Remote/local file inclusion: request data controls an include/require path, enabling code execution.",
		"Never include files based on user input; use a whitelist of allowed templates/pages.",
		exts(".php"),
		`\b(include|include_once|require|require_once)\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)`,
		"", "", ""),
	rule("builtin.code-execution.php", "high",
		"Arbitrary code execution: eval() executes a string, which is critical when it can carry user input.",
		"Remove eval() calls; use safe alternatives for dynamic behavior.",
		exts(".php"),
		`\beval\s*\(`, "", "", ""),
	rule("builtin.unsafe-deserialization.php", "medium",
		"Unsafe deserialization: unserialize() of request-controlled data can trigger object injection / code execution.",
		"Never unserialize untrusted data; prefer json_decode and validate the input.",
		exts(".php"),
		`unserialize\s*\(`,
		`\$_(GET|POST|REQUEST|COOKIE)`, "", ""),

	// ---------------- Go ----------------
	rule("builtin.sql-injection.go", "high",
		"SQL injection: database.Query/Exec is called with a SQL string built by concatenation or fmt.Sprintf.",
		"Use parameter placeholders (db.Query(sql, args...)) and never concatenate input into SQL.",
		exts(".go"),
		`\.(Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext)\s*\(`,
		`(\+\s*["'`+"`"+`]|["'`+"`"+`]\s*\+|fmt\.Sprintf\s*\(|strings\.Builder)`,
		`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b`, ""),
	rule("builtin.command-injection.go", "high",
		"Command injection: exec.Command builds a shell command from concatenated values.",
		"Pass arguments as separate exec.Command parameters and avoid shell -c wrappers; validate input.",
		exts(".go"),
		`exec\.Command\s*\(`,
		`(\+|(-c|-C)\s*["']|/bin/(ba)?sh|cmd\.exe)`, "", ""),
	rule("builtin.weak-crypto.go", "medium",
		"Weak cryptography: MD5/SHA-1/DES are broken and must not be used for security.",
		"Use crypto/sha256, crypto/rand or a modern AEAD (AES-GCM) instead of md5/sha1/des.",
		exts(".go"),
		`(?i)\b(md5|sha1|des)\.`, "", "", ""),

	// ---------------- Java / Kotlin ----------------
	rule("builtin.sql-injection.java", "high",
		"SQL injection: a JDBC statement is executed with a SQL string built by concatenation.",
		"Use PreparedStatement with bound parameters; never concatenate input into SQL.",
		exts(".java", ".kt", ".kts"),
		`\.(executeQuery|executeUpdate|execute)\s*\(`,
		`\s*\+`,
		`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b`, ""),
	rule("builtin.command-injection.java", "high",
		"Command injection: Runtime.exec / ProcessBuilder builds a shell command from concatenated values.",
		"Pass arguments as a String array / ProcessBuilder list and never concatenate input into shell commands.",
		exts(".java", ".kt", ".kts"),
		`(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(`,
		`\s*\+`, "", ""),
	rule("builtin.unsafe-deserialization.java", "high",
		"Unsafe deserialization: ObjectInputStream is vulnerable to gadget-chain attacks on untrusted data.",
		"Never deserialize untrusted data; prefer JSON/allowlist-based formats and validate sources.",
		exts(".java"),
		`\bObjectInputStream\b`, "", "", ""),
	rule("builtin.weak-crypto.java", "medium",
		"Weak cryptography: MD5/SHA-1/DES algorithms are broken and must not be used.",
		"Use SHA-256+ with a salt, or AES-GCM for encryption.",
		exts(".java", ".kt", ".kts"),
		`(?i)getInstance\s*\(\s*"(MD5|SHA-?1|DES|DESede)`, "", "", ""),
	rule("builtin.xss.java", "medium",
		"Cross-site scripting: request data is written directly into the HTTP response.",
		"Escape output for the HTML context (e.g. OWASP Java Encoder) before writing it to the response.",
		exts(".java"),
		`response\.getWriter\(\)\.(println|print|write)\s*\(`,
		`request\.(getParameter|getHeader)`, "", ""),

	// ---------------- Ruby ----------------
	rule("builtin.command-injection.ruby", "high",
		"Command injection: system/exec/Open3 builds a shell command from interpolated or concatenated values.",
		"Pass arguments as separate array elements (system('cmd', arg)) and never interpolate input into shell strings.",
		exts(".rb"),
		`\b(system|exec|spawn|Open3\.(capture2|capture3|popen2|popen3))\s*\(`,
		`(#\{|\s*\+|"\$)`, "", ""),
	rule("builtin.sql-injection.ruby", "high",
		"SQL injection: an ActiveRecord query is built with string interpolation.",
		"Use parameterized where clauses (where('name = ?', name)) and never interpolate input into SQL.",
		exts(".rb"),
		`\.where\s*\(?\s*["']|\.(find_by_sql|execute)\s*\(`,
		`#\{`, "", ""),
	rule("builtin.code-execution.ruby", "high",
		"Arbitrary code execution: eval/instance_eval executes a string that may contain untrusted data.",
		"Remove eval calls; use safe alternatives for dynamic behavior.",
		exts(".rb"),
		`\b(eval|instance_eval|class_eval)\s*\(`,
		`(#\{|\s*\+|"\$|request)`, "", ""),
	rule("builtin.unsafe-deserialization.ruby", "medium",
		"Unsafe deserialization: Marshal.load / YAML.load can execute arbitrary objects from untrusted data.",
		"Never deserialize untrusted data with Marshal; use YAML.safe_load and validate sources.",
		exts(".rb"),
		`(Marshal\.load|YAML\.load)\s*\(`, "", "", ""),

	// ---------------- C# ----------------
	rule("builtin.sql-injection.csharp", "high",
		"SQL injection: a SQL command is built by string concatenation.",
		"Use parameterized commands (SqlCommand with Parameters.Add) and never concatenate input into SQL.",
		exts(".cs"),
		`\.(ExecuteQuery|ExecuteNonQuery|ExecuteReader|ExecuteScalar)\s*\(`,
		`\s*\+`,
		`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b`, ""),
	rule("builtin.command-injection.csharp", "high",
		"Command injection: Process.Start builds a shell command from concatenated values.",
		"Pass arguments as a separate list (ProcessStartInfo.ArgumentList) and never concatenate input into shell commands.",
		exts(".cs"),
		`Process\.Start\s*\(`,
		`\s*\+`, "", ""),
	rule("builtin.unsafe-deserialization.csharp", "high",
		"Unsafe deserialization: BinaryFormatter is a known code-execution risk on untrusted data.",
		"Replace BinaryFormatter with a safe serialization format (System.Text.Json) and validate sources.",
		exts(".cs"),
		`\bBinaryFormatter\b`, "", "", ""),

	// ---------------- C / C++ ----------------
	rule("builtin.unsafe-string.c", "high",
		"Memory-unsafe string function: strcpy/strcat/gets/sprintf can overflow buffers when fed untrusted input.",
		"Use bounded variants (strncpy/strncat/snprintf) with explicit sizes, or std::string / std::string_view in C++.",
		exts(".c", ".cpp", ".cc", ".h", ".hpp"),
		`\b(strcpy|strcat|sprintf|gets|scanf)\s*\(`, "", "", ""),
	rule("builtin.command-injection.c", "high",
		"Command injection: system/popen executes a shell command built with concatenated or unvalidated data.",
		"Pass arguments via execve-family calls without a shell; never let untrusted input reach a shell string.",
		exts(".c", ".cpp", ".cc"),
		`\b(system|popen)\s*\(`,
		`(\s*\+|snprintf\s*\(|sprintf\s*\(|argv|getenv|fgets|fscanf|cin\s*>>)`, "", ""),
	rule("builtin.format-string.c", "medium",
		"Format-string vulnerability: a non-literal string is used as the format argument of a printf-family call.",
		"Always pass a literal format string; pass variables as arguments, never as the format itself.",
		exts(".c", ".cpp", ".cc", ".h", ".hpp"),
		`\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(,|\))`,
		"", "", `stderr|stdout|LOG_`),

	// ---------------- C# ----------------
	rule("builtin.xss.csharp", "high",
		"Cross-site scripting: request data is written straight into the HTTP response unescaped.",
		"HTML-encode response output (HttpUtility.HtmlEncode / Razor auto-encoding); never echo request data raw.",
		exts(".cs"),
		`Response\.(Write|Output\.Write)\s*\(`,
		`Request\.(QueryString|Form|Headers|Params)`, "", ""),

	// ---------------- Swift ----------------
	rule("builtin.unsafe-deserialization.swift", "high",
		"Unsafe deserialization: NSKeyedUnarchiver can instantiate arbitrary classes from untrusted data.",
		"Use Codable + JSONDecoder with a strict allowlist and validate the data source.",
		exts(".swift"),
		`NSKeyedUnarchiver\.(unarchiveTopLevelObjectWithData|unarchiveObjectWithData|unarchivedObjectOfClass)`, "", "", ""),
	rule("builtin.weak-crypto.swift", "medium",
		"Weak cryptography: MD5/SHA-1 are cryptographically broken.",
		"Use CryptoKit SHA256+ or CommonCrypto with a modern algorithm.",
		exts(".swift"),
		`(?i)\b(MD5|SHA1|Insecure\.(md5|sha1))`, "", "", ""),

	// ---------------- HTML / templates ----------------
	rule("builtin.xss.html-inline", "medium",
		"Inline event handler or javascript: URL — a common XSS sink when it reflects untrusted data.",
		"Avoid inline handlers; use addEventListener with sanitized values and a CSP without 'unsafe-inline'.",
		exts(".html", ".htm", ".jsp", ".cshtml", ".erb", ".twig"),
		`(?i)\son[a-z]+\s*=|(?i)href\s*=\s*["']?\s*javascript:`, "", "", ""),

	// ---------------- Shell ----------------
	rule("builtin.command-injection.shell", "high",
		"Command injection: eval is used on a string that references shell variables.",
		"Remove eval; expand variables directly or use arrays to pass arguments safely.",
		exts(".sh", ".bash", ".zsh"),
		`\beval\s+`, `\$`, "", ""),
	rule("builtin.download-execute.shell", "medium",
		"Risky pattern: a remote script is downloaded and piped straight into a shell, executing unverified code.",
		"Download the script, verify its checksum/signature, then execute it explicitly.",
		exts(".sh", ".bash", ".zsh"),
		`(?i)\b(curl|wget)\b[^|\n]*\|\s*(sh|bash)\b`, "", "", ""),

	// ---------------- Dockerfile ----------------
	rule("builtin.docker-add-url", "medium",
		"Dockerfile ADD fetches a remote resource over the network instead of using a pinned, verified artifact.",
		"Prefer COPY from a local build context or curl with checksum verification; never ADD remote URLs.",
		nil,
		`^\s*ADD\s+https?://`, "", "", ""),
	rule("builtin.docker-privileged", "high",
		"Container runs with --privileged (or privileged: true), disabling most kernel isolation.",
		"Remove --privileged and grant only the Linux capabilities the process actually needs.",
		nil,
		`(?i)--privileged|privileged\s*[:=]\s*(true|yes|1)`, "", "", ""),
	rule("builtin.docker-remote-script", "medium",
		"Dockerfile RUN downloads and pipes a remote script straight into a shell, executing unverified code.",
		"Pin the script URL and verify its checksum before execution; never pipe unverified downloads to sh.",
		nil,
		`(?i)^\s*RUN\b[^\n]*(curl|wget)\b[^\n]*\|\s*(sh|bash)\b`, "", "", ""),

	// ---------------- Terraform / IaC ----------------
	rule("builtin.terraform-open-ingress", "high",
		"Open ingress: a CIDR block allows the whole internet (0.0.0.0/0) into a resource.",
		"Narrow the CIDR to the networks that actually need access; never use 0.0.0.0/0 on ingress rules.",
		exts(".tf"),
		`(?i)cidr_blocks?\s*=\s*\[?["']?0\.0\.0\.0/0`, "", "", ""),
	rule("builtin.terraform-s3-public", "medium",
		"S3 bucket is configured for public reads (acl = public-read / public_access_block disabled).",
		"Remove public ACLs and keep the public access block enabled unless the bucket is intentionally public.",
		exts(".tf"),
		`(?i)acl\s*=\s*["']public-read["']|block_public_acls\s*=\s*false`, "", "", ""),

	// ---------------- Kubernetes / YAML ----------------
	rule("builtin.k8s-privileged", "high",
		"Workload runs privileged, with hostNetwork, or with privilege escalation enabled — weak node isolation.",
		"Use restricted security contexts (no privileged, no hostNetwork, allowPrivilegeEscalation: false).",
		exts(".yaml", ".yml"),
		`(?i)(privileged\s*:\s*true|hostNetwork\s*:\s*true|allowPrivilegeEscalation\s*:\s*true)`, "", "", ""),
}

// skippedDirs are never descended into during the scan.
var skippedDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".next": true, ".nuxt": true, "target": true, "__pycache__": true, ".venv": true,
	"venv": true, ".tox": true, ".cache": true, ".idea": true, ".vscode": true,
	"coverage": true, ".terraform": true, ".serverless": true,
}

// textExts is the set of file extensions scanned as source/config text.
var textExts = exts(
	".go", ".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".kt", ".kts", ".rs",
	".php", ".rb", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".swift", ".scala",
	".sh", ".bash", ".zsh", ".lua", ".r", ".m", ".vue", ".svelte", ".sql", ".ps1", ".pl",
	".json", ".yaml", ".yml", ".toml", ".ini", ".properties", ".xml", ".conf", ".cfg",
	".tf", ".hcl", ".dockerfile",
	".txt", ".md", ".html", ".htm", ".jsp", ".cshtml", ".erb", ".twig",
)

// textNames are extensionless files treated as text (Dockerfile, Makefile, .env...).
var textNames = map[string]bool{
	"dockerfile": true, "makefile": true, "jenkinsfile": true, ".env": true,
	".htaccess": true, ".gitignore": true, "procfile": true, "rakefile": true,
}

// Run walks the project and applies every rule. It always records a status:
// success when the scan completed (even with zero findings — that is a real
// clean result from a scanner that actually ran), error only on an internal
// failure.
func (b *BuiltinRunner) Run(projectPath string, status *ToolStatusCollector) []models.SecurityFinding {
	outcome := &ToolOutcome{Tool: builtinToolName}
	start := time.Now()
	defer func() {
		outcome.Duration = time.Since(start)
		status.Record(outcome)
	}()

	deadline := start.Add(b.timeout)
	findings := []models.SecurityFinding{}
	counts := map[string]int{} // ruleID -> findings so far (global)

	walkErr := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if path != projectPath && skippedDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if len(findings) >= b.maxFindings || time.Now().After(deadline) {
			return errStopScan
		}
		b.scanFile(projectPath, path, &findings, counts, deadline, b.maxFindings)
		return nil
	})
	if walkErr != nil && walkErr != errStopScan {
		outcome.Status = statusError
		outcome.Error = "builtin scan failed: " + walkErr.Error()
		return nil
	}

	outcome.Status = statusSuccess
	outcome.Findings = len(findings)
	if len(findings) >= b.maxFindings {
		outcome.Error = "findings cap reached; the report is truncated to the first " + strconv.Itoa(b.maxFindings) + " results"
	} else if time.Now().After(deadline) {
		outcome.Error = "scan stopped at its time budget (" + b.timeout.String() + "); results may be partial"
	}
	return findings
}

// scanFile applies the language and secret rules to one source file.
func (b *BuiltinRunner) scanFile(projectPath, path string, findings *[]models.SecurityFinding, counts map[string]int, deadline time.Time, maxFindings int) {
	name := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	// Anything that looks like an environment file (*.env, prod.env, ...) is
	// scanned for secrets even though it has no source extension.
	if !textExts[ext] && !textNames[name] && !strings.HasSuffix(name, ".env") {
		return
	}

	info, err := os.Stat(path)
	if err != nil || info.Size() > builtinMaxFileBytes {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil || len(data) > builtinMaxFileBytes {
		return
	}
	// Binary sniff: source files must not contain NUL bytes.
	if bytes.IndexByte(data[:min(len(data), 8192)], 0) >= 0 {
		return
	}

	rel := relPath(projectPath, path)
	lines := strings.Split(string(data), "\n")

	// Per-file state: whether this file aliases child_process, so the JS
	// command-injection rule honors `const cp = require('child_process')`.
	hasChildProcess := false

	applicable := builtinRules
	for i := range applicable {
		r := &applicable[i]
		if r.exts != nil && !r.exts[strings.ToLower(filepath.Ext(path))] {
			continue
		}
		perFile := 0
		for lineNo, line := range lines {
			if len(*findings) >= maxFindings {
				return
			}
			if time.Now().After(deadline) {
				return
			}
			if reRequireChildProcess.MatchString(line) {
				hasChildProcess = true
			}
			if !r.trigger.MatchString(line) {
				continue
			}
			if r.id == "builtin.command-injection.javascript" && !hasChildProcess && !strings.Contains(line, "child_process") {
				continue
			}
			if r.condition != nil && !r.condition.MatchString(line) {
				continue
			}
			if r.context != nil && !r.context.MatchString(line) {
				continue
			}
			if r.skip != nil && r.skip.MatchString(line) {
				continue
			}
			counts[r.id]++
			perFile++
			*findings = append(*findings, models.SecurityFinding{
				Rule:           r.id,
				FilePath:       rel,
				LineNumber:     lineNo + 1,
				Severity:       r.severity,
				Description:    r.description + " [" + truncate(strings.TrimSpace(line), 120) + "]",
				Recommendation: r.recommendation,
				Tool:           builtinToolName,
			})
			if perFile >= builtinPerRulePerFile {
				break
			}
		}
	}

	b.checkSecrets(rel, lines, findings, maxFindings, deadline)
}

// namedSecret is a high-signal secret pattern checked on every text line.
type namedSecret struct {
	re          *regexp.Regexp
	severity    string
	description string
}

var namedSecrets = []namedSecret{
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "high", "AWS Access Key ID hardcoded in source"},
	{regexp.MustCompile(`(?i)\baws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["']?[A-Za-z0-9/+=]{20,}`), "high", "AWS secret access key hardcoded in source"},
	{regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{20,}\b`), "high", "GitHub personal access token hardcoded in source"},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), "high", "Google API key hardcoded in source"},
	{regexp.MustCompile(`\bGOCSPX-[0-9A-Za-z_\-]{20,}\b`), "high", "Google OAuth client secret hardcoded in source"},
	{regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`), "high", "Slack token hardcoded in source"},
	{regexp.MustCompile(`\b(?:sk|pk)[_-](?:test|live)[_-][0-9A-Za-z]{16,}\b`), "high", "Stripe API key hardcoded in source"},
	{regexp.MustCompile(`\bsk-(proj|ant|svc)-[A-Za-z0-9_\-]{20,}\b`), "high", "OpenAI/Anthropic API key hardcoded in source"},
	{regexp.MustCompile(`\bhf_[A-Za-z0-9]{20,}\b`), "high", "Hugging Face access token hardcoded in source"},
	{regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{16,}\b`), "high", "SendGrid API key hardcoded in source"},
	{regexp.MustCompile(`\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b`), "high", "Telegram bot token hardcoded in source"},
	{regexp.MustCompile(`(?i)//registry\.npmjs\.org/:_authToken\s*=\s*[A-Za-z0-9_\-]{20,}`), "high", "npm registry auth token hardcoded in source"},
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`), "high", "Private key material embedded in source"},
	{regexp.MustCompile(`(?i)\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s/@]+:[^@\s/]+@`), "high", "Database connection string embeds credentials"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`), "medium", "JWT token (potentially valid credential) hardcoded in source"},
}

// genericSecret is the catch-all for `password = "..."` style assignments. The
// key may be underscore-prefixed (DB_PASSWORD, GITHUB_TOKEN, ...) and the
// value may be quoted or unquoted (.env style).
// The leading boundary keeps the key match from firing inside longer words
// ("superpassword"), and the value may be quoted or unquoted (.env style).
var genericSecret = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(api[_-]?key|secret|token|passwd|password|pwd)\s*[=:]\s*["']?([A-Za-z0-9_\-/+=.!@#$%^&*()]{12,})["']?`)

// reRequireChildProcess detects the `const cp = require('child_process')` alias
// used across Node projects so the JS command-injection rule can honor it.
var reRequireChildProcess = regexp.MustCompile(`require\s*\(\s*["']child_process["']`)

// secretPlaceholders are values that are obviously not real secrets.
var secretPlaceholders = regexp.MustCompile(`(?i)your|xxx|example|changeme|placeholder|sample|dummy|todo|insert|replace|<|>|^\$|env\(|getenv|process\.env|os\.environ|random`)

// checkSecrets flags hardcoded credentials on every line of a text file.
func (b *BuiltinRunner) checkSecrets(rel string, lines []string, findings *[]models.SecurityFinding, maxFindings int, deadline time.Time) {
	ruleCount := 0
	for lineNo, line := range lines {
		if len(*findings) >= maxFindings {
			return
		}
		if time.Now().After(deadline) {
			return
		}
		trimmed := strings.TrimSpace(line)

		namedHit := false
		for _, ns := range namedSecrets {
			if !ns.re.MatchString(trimmed) {
				continue
			}
			namedHit = true
			ruleCount++
			*findings = append(*findings, models.SecurityFinding{
				Rule:           "builtin.secret." + ns.description,
				FilePath:       rel,
				LineNumber:     lineNo + 1,
				Severity:       ns.severity,
				Description:    ns.description + " [" + truncate(trimmed, 120) + "]",
				Recommendation: "Remove the secret from source, rotate it immediately, and load it from environment variables / a secret manager.",
				Tool:           builtinToolName,
			})
			if ruleCount >= builtinPerRulePerFile*2 {
				return
			}
		}
		if namedHit {
			continue
		}

		if m := genericSecret.FindStringSubmatch(trimmed); m != nil {
			value := m[2]
			if secretPlaceholders.MatchString(value) || len(value) > 128 {
				continue
			}
			ruleCount++
			*findings = append(*findings, models.SecurityFinding{
				Rule:           "builtin.secret.hardcoded-credential",
				FilePath:       rel,
				LineNumber:     lineNo + 1,
				Severity:       "medium",
				Description:    "Hardcoded credential in source (" + m[1] + ") [" + truncate(trimmed, 120) + "]",
				Recommendation: "Load credentials from environment variables / a secret manager instead of committing them.",
				Tool:           builtinToolName,
			})
			if ruleCount >= builtinPerRulePerFile*2 {
				return
			}
		}
	}
}
