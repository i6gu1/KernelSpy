# Debugging Checklist — "No vulnerabilities found" (false negatives)

This checklist walks you through proving that the fixed pipeline actually
catches deliberately vulnerable code, and — just as important — that it *never
again* reports a clean scan when a scanner silently failed to run.

## The fix in one paragraph

Every scanner now records a **ToolStatus** (success | missing | timeout |
error) into the report. The summary is honest: if any scanner could not run,
the report says the scan **may be INCOMPLETE** and shows a **Scanner Status**
table (web results page, JSON and HTML reports) listing each tool, its status,
findings count, duration and error. A missing binary can no longer masquerade
as "no vulnerabilities".

---

## 1. Verify the tools are installed

```bash
# In the Docker image (recommended — full toolchain):
docker compose up --build
docker compose exec app sh -c 'for t in semgrep bandit njsscan eslint gosec gitleaks trivy codeql dependency-check.sh; do command -v $t >/dev/null && echo "OK   $t -> $(command -v $t)" || echo "MISS $t"; done'

# Or on your host:
bash build.sh    # installs everything into /opt/bin (may need sudo)
```

Expected: every line prints `OK`. Any `MISS` line is *fine for local dev*, but
remember that scanner will report **missing** in the Scanner Status table — it
will not silently produce an empty report.

## 2. Create the deliberately vulnerable fixture

Save this as `vulnerable-test/` and zip it (`vulnerable-test.zip`):

```python
# vulnerable-test/app.py  — SQL injection + hardcoded secret + RCE
import sqlite3
import subprocess

DB_PASSWORD = "P@ssw0rd123-SUPERSECRET"

def get_user(name):
    con = sqlite3.connect("app.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # SQLi
    return cur.fetchall()

def run_cmd(cmd):
    return subprocess.call("ping " + cmd, shell=True)               # RCE
```

```javascript
// vulnerable-test/server.js  — unsanitized eval + hardcoded AWS key
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
app.get("/search", (req, res) => {
  const q = req.query.q;
  res.send(eval("resultsFor('" + q + "')"));   // code injection
});
```

```bash
cd vulnerable-test && zip -r ../vulnerable-test.zip . && cd ..
```

## 3. Scan it and check the report

1. Start the server (`docker compose up --build`, then http://localhost:3000).
2. Upload `vulnerable-test.zip`.
3. Wait for the analysis to finish, then open the results page.

**Expected results:**

| Tool              | Status  | What it should find                        |
|-------------------|---------|--------------------------------------------|
| Semgrep           | success | SQL injection, eval/code injection, secrets |
| Bandit            | success | B608 SQL injection, B105 hardcoded password |
| NjsScan           | success | code injection / unsafe eval                |
| Gitleaks          | success | the AWS key + DB_PASSWORD                   |
| ESLint (security) | success | `detect-eval-with-expression`, no-secrets   |
| CodeQL            | success | SQL injection data-flow, eval sink          |
| Trivy / DepCheck  | success | (nothing, unless you add a lockfile)        |

The report must **NOT** say `No vulnerabilities were detected by the static
analysis tools.` It must list findings from at least Semgrep and Bandit.

## 4. The fail-safe test (the critical one)

Deliberately break one tool, then re-scan:

```bash
# Make semgrep unavailable, then rescan:
docker compose exec app mv /usr/local/bin/semgrep /usr/local/bin/semgrep.bak
# or, outside Docker: rename the binary on your PATH
```

Re-scan the same fixture. **The report must now say** the scan is
**INCOMPLETE**, show `semgrep (missing)` in the Scanner Status table, and still
show the findings from the other scanners. If it ever shows the plain
"no vulnerabilities" sentence while a scanner is missing, the fail-safe is
broken — file a bug.

## 5. Manual CLI verification (bypass the web UI)

```bash
# Run the exact commands the pipeline runs, to isolate a scanner:
semgrep --config=auto --json --quiet --metrics=off --disable-version-check --timeout=30 --jobs=2 vulnerable-test/
bandit -r vulnerable-test -f json -q
gitleaks detect --source vulnerable-test --report-format json --report-path /tmp/gl.json --no-banner
trivy fs --format json --quiet --scanners vuln,secret,misconfig --skip-dirs node_modules --skip-dirs .git vulnerable-test/
```

Check the JSON is valid and contains findings before blaming the pipeline.

## 6. Common causes of "still nothing found"

- **You're on Vercel / serverless**: no SAST tools exist in that sandbox, so
  *every* scanner shows `missing` and the summary says INCOMPLETE. Deploy the
  Docker image for real scans (README has instructions).
- **Semgrep offline**: `--config=auto` downloads rules from the network. Point
  `SEMGREP_CONFIG` at a local rules directory for offline use, or pre-warm the
  registry cache in the image.
- **Trivy offline**: first run downloads its vulnerability DB. With no network
  or no `TRIVY_CACHE_DIR` volume, trivy reports `error` — you'll see it in the
  table now, instead of a fake clean result.
- **Dependency-Check first run**: downloads the NVD feed and can take 20+
  minutes. Mount `/opt/dependency-check/data` as a volume (docker-compose does)
  and raise `DEPCHECK_TIMEOUT_SECONDS` if needed.
- **Your test file has no recognized extension**: `.txt`/`.md` files trigger no
  language scanner; Semgrep is still the best bet, but use real `.py`/`.js`
  files for testing.

## 7. Regression check

```bash
go test ./services/ -run TestAnalyzeVulnerablePythonProject -v
```

The smoke test uploads a vulnerable Python file and asserts Bandit's status was
recorded and — when Bandit actually ran — that findings were produced. It also
asserts the summary never hides a missing scanner behind a clean sentence.
