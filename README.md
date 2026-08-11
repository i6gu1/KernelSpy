# Black Hat

A code analysis platform that detects security issues, dependency vulnerabilities and code quality problems using **industry-standard Static Application Security Testing (SAST) CLI tools** plus a **built-in zero-dependency pattern analyzer**. No AI is used — every finding comes strictly from deterministic analysis.

![Black Hat](https://img.shields.io/badge/Black_Hat-Code_Analysis-000000?style=for-the-badge&labelColor=000000&color=ffffff)
![Go](https://img.shields.io/badge/Go-1.21-00ADD8?style=for-the-badge&logo=go&logoColor=white)

## Features

- **Security Analysis** — runs Semgrep, Gosec, Bandit, Njsscan, ESLint (security rules), Gitleaks and **CodeQL** concurrently and aggregates their JSON/SARIF findings
- **Built-in Zero-Dependency Analyzer** — a pure-Go pattern analyzer (SQL injection, XSS, command injection, hardcoded secrets, weak crypto, unsafe deserialization, ...) that ALWAYS runs and produces real findings even when no external SAST tools are installed (e.g. serverless sandboxes like Vercel)
- **Dependency Analysis** — Trivy **and OWASP Dependency-Check** report known vulnerabilities (CVEs) in your dependencies
- **Code Quality** — ESLint, golangci-lint, Clippy, PMD and PHPStan findings plus quality metrics
- **Fail-safe Scanner Status** — every scanner records its outcome (success/missing/timeout/error) into the report, so a tool that could not run is shown and the summary warns the scan may be incomplete — a missing tool can never masquerade as a clean scan
- **Reports** — export detailed reports in JSON and HTML formats
- **Multi-Language** — support for 5 languages: English, Arabic, Russian, French, Spanish
- **RTL Support** — full Right-to-Left layout support for Arabic
- **Premium Design** — premium black-and-white aesthetic with smooth animations

## Analysis Tools

| Tool | Purpose | Language |
|------|---------|----------|
| Built-in pattern analyzer | SQL injection, XSS, command injection, secrets, weak crypto, deserialization (zero dependencies, always runs) | All |
| Semgrep | Security scanning (XSS, SQL Injection, Command Injection, SSRF) | All |
| CodeQL | Deep data-flow / taint-tracking analysis (zero-day logic flaws) | Go/Python/JS/TS/Ruby/Java/Kotlin/C#/C++/Swift |
| Gitleaks | API keys, AWS keys, tokens, passwords | All |
| Trivy | Dependency vulnerabilities + secrets + IaC misconfig | All |
| OWASP Dependency-Check | SCA: npm, pip, maven, gradle, nuget, composer, gem, cargo, go.mod | All |
| Gosec | Go security scanner | Go |
| Bandit | Python security linter | Python |
| Njsscan | Node.js security scanner | JS/TS |
| ESLint + security plugins | JS/TS linting + security rules | JS/TS |
| golangci-lint / Clippy / PMD / PHPStan | Code quality | Go/Rust/Java/PHP |

Tools are discovered at runtime from `CODQL_HOME`, `DEPENDENCY_CHECK_HOME`, `SAST_TOOLS_DIR`, `/opt/bin`, `/usr/local/bin` and `PATH`. **Fail-safe:** every scanner records a status in the report's **Scanner Status** section. A missing/timed-out/crashed scanner is surfaced there and the summary warns the scan may be incomplete — the pipeline never reports a clean scan because a tool silently failed to run. The **built-in analyzer always succeeds**, so even a serverless deployment with no external tools installed still returns a real report. See `DEBUGGING.md` for the full debugging checklist.

## Tech Stack

- **Backend:** Go (net/http, no framework)
- **Frontend:** Go Templates + Alpine.js (unchanged)
- **Styling:** Custom CSS (no frameworks)
- **Deployment:** Vercel Go functions (serverless) or Docker

## Quick Start

### Prerequisites

- Go 1.21+

### Local Development

```bash
go mod tidy
go run ./cmd/api
```

Visit `http://localhost:3000`

### Installing SAST tools locally (optional)

```bash
bash build.sh                 # installs tools into /opt/bin (may need sudo)
# or point at a custom dir:
SAST_TOOLS_DIR=./tools bash build.sh && export SAST_TOOLS_DIR=./tools
```

### Docker

```bash
docker-compose up --build
# or
docker build -t black-hat .
docker run -p 3000:3000 black-hat
```

The Docker image installs the full SAST toolchain via `build.sh`, so all scanners run inside the container.

### Environment Variables

```env
PORT=3000
ENV=production
DATABASE_URL=postgres://user:password@localhost:5432/blackhat?sslmode=disable
REDIS_URL=localhost:6379
MAX_UPLOAD_SIZE=52428800
SAST_TOOLS_DIR=/opt/bin
ANALYSIS_TIMEOUT=600
MAX_CONCURRENT_ANALYSES=5

# Scanner tuning (fail-safe):
CODQL_HOME=/opt/codeql                  # CodeQL install root (binary at $CODQL_HOME/codeql)
DEPENDENCY_CHECK_HOME=/opt/dependency-check
TRIVY_CACHE_DIR=/opt/trivy-cache        # persist the trivy vuln DB across restarts
SAST_TOOL_TIMEOUT_SECONDS=300           # per-tool cap for the standard scanners
CODQL_TIMEOUT_SECONDS=600               # per language for CodeQL db create + analyze
DEPCHECK_TIMEOUT_SECONDS=600            # Dependency-Check first run downloads NVD data
SEMGREP_CONFIG=auto                     # semgrep rule source; set to a local dir for offline
SAST_CODQL_ENABLED=1                    # 0 to disable CodeQL entirely
CODQL_LANGUAGES=                        # optional restrict, e.g. javascript,go
DEPCHECK_EXTRA_ARGS=                    # optional extra depcheck flags, e.g. --disableRetireJS
BUILTIN_TIMEOUT_SECONDS=45              # cap for the built-in pattern analyzer (fits serverless budgets)
BUILTIN_MAX_FINDINGS=500                # max findings the built-in analyzer reports
```

## How it works

1. **Upload** — the Go backend parses `multipart/form-data` with `net/http`, saves the ZIP under the OS temp dir (`/tmp` on Vercel — the only writable location), and extracts it with `archive/zip` under strict guards (path-traversal rejection, per-file and total expansion caps against zip bombs, entry-count limit).
2. **Detect** — the project's languages and frameworks are detected from the extracted tree.
3. **Scan (concurrently)** — every applicable SAST tool runs in its own goroutine (`sync.WaitGroup` + mutex-aggregated results). Each tool's JSON output is unmarshaled into typed Go structs.
4. **Aggregate** — findings are unified into a single report: severity, file path, line number, description and the tool that produced each finding.
5. **Clean up** — the extracted project and uploaded archive are deleted from `/tmp` after the scan.

## Project Structure

```
black-hat/
├── cmd/api/                  # Go server entry point (Vercel Go Framework Preset + local)
├── assets.go                 # go:embed of templates/static/i18n (required on Vercel)
├── config/                   # Configuration loading
├── i18n/                     # Translation files (en, ar, ru, fr, es)
├── handlers/                 # net/http handlers (pages + API)
├── models/                   # Data models (JSON schema)
├── services/                 # SAST tool runners + analyzer + extractor
├── middleware/               # net/http middleware + rate limiter
├── templates/                # HTML templates (embedded)
├── static/                   # CSS, JS, images (embedded)
└── build.sh                  # Installs SAST binaries into /opt/bin during builds
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Home page |
| GET | `/upload` | Upload page |
| GET | `/results/:id` | Analysis results |
| GET | `/reports/:id` | Report download page |
| POST | `/api/upload` | Upload a ZIP project for analysis |
| GET | `/api/analysis/status/:id` | Check analysis status |
| GET | `/api/results/security/:id` | Security findings |
| GET | `/api/results/quality/:id` | Quality findings + metrics |
| GET | `/api/results/dependencies/:id` | Dependency vulnerabilities |
| GET | `/api/reports/:id/:format` | Download report (json/html) |
| GET | `/health` | Health check |

## Deployment

### Vercel (serverless Go function)

The app uses Vercel's **Go Framework Preset**: Vercel detects the root
`go.mod` plus the `cmd/api/main.go` entrypoint (the documented `go` preset
layout), and runs the net/http server bound to `$PORT`. `templates`, `static`
and `i18n` are embedded into the binary with `go:embed` so no extra files are
needed at runtime. Uploads are written to `os.TempDir()` (`/tmp`), the only
writable location in the runtime sandbox.

```bash
vercel link
vercel --prod
```

> **Note:** On Vercel's Go server runtime the app runs as a long-lived
> process and `/tmp` is writable. The analysis is run synchronously inside the
> upload request (serverless workers freeze idle background goroutines, so no
> polling dead-ends). SAST tools installed by `build.sh` are not present in
> Vercel's runtime sandbox, so those scanners show `missing` in the Scanner
> Status section — but the **built-in analyzer still scans the code and
> reports real findings** (SQL injection, XSS, command injection, hardcoded
> secrets, ...). For the deepest results, deploy the **Docker image**
> (Render, Fly.io, a VPS, or any container host) where the full external
> toolchain also runs.

### Docker (full SAST toolchain)

1. Connect the repository to Render/Fly/any container host.
2. Build the Dockerfile — it compiles the Go app and runs `build.sh` to install every SAST tool into the image.
3. Set `PORT=80` if your host expects it.

## Supported Languages

| Language | Code | Direction | Default |
|----------|------|-----------|---------|
| English | en | LTR | Yes |
| Arabic | ar | RTL | No |
| Russian | ru | LTR | No |
| French | fr | LTR | No |
| Spanish | es | LTR | No |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the [MIT License](LICENSE).

## Developers

Developed by **The L house**:
- Mohammed Aloush
- AbdulRahman Bakir
- Maria Mohammed

## Contact

- GitHub: [i6gu1](https://github.com/i6gu1/Black-hat)
- Email: nvapps@proton.me
- Instagram: [real.lm2](https://www.instagram.com/real.lm2)
