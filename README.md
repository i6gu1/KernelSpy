# Black Hat

A code analysis platform that detects security issues, dependency vulnerabilities and code quality problems using **industry-standard Static Application Security Testing (SAST) CLI tools**. No AI is used — every finding comes strictly from the tools' outputs.

![Black Hat](https://img.shields.io/badge/Black_Hat-Code_Analysis-000000?style=for-the-badge&labelColor=000000&color=ffffff)
![Go](https://img.shields.io/badge/Go-1.21-00ADD8?style=for-the-badge&logo=go&logoColor=white)

## Features

- **Security Analysis** — runs Semgrep, Gosec, Bandit, Njsscan, ESLint (security rules) and Gitleaks concurrently and aggregates their JSON findings
- **Dependency Analysis** — Trivy reports known vulnerabilities in your dependencies
- **Code Quality** — ESLint, golangci-lint, Clippy, PMD and PHPStan findings plus quality metrics
- **Reports** — export detailed reports in JSON and HTML formats
- **Multi-Language** — support for 5 languages: English, Arabic, Russian, French, Spanish
- **RTL Support** — full Right-to-Left layout support for Arabic
- **Premium Design** — premium black-and-white aesthetic with smooth animations

## Analysis Tools

| Tool | Purpose | Language |
|------|---------|----------|
| Semgrep | Security scanning (XSS, SQL Injection, Command Injection, SSRF) | All |
| Gitleaks | API keys, AWS keys, tokens, passwords | All |
| Trivy | Dependency vulnerabilities, CVEs | All |
| Gosec | Go security scanner | Go |
| Bandit | Python security linter | Python |
| Njsscan | Node.js security scanner | JS/TS |
| ESLint + security plugins | JS/TS linting + security rules | JS/TS |
| golangci-lint / Clippy / PMD / PHPStan | Code quality | Go/Rust/Java/PHP |

Tools are discovered at runtime from `SAST_TOOLS_DIR`, `/opt/bin`, `/usr/local/bin` and `PATH`. Missing tools are skipped gracefully — the pipeline never fails because a tool isn't installed.

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
go run ./cmd/blackhat
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
├── api/handler.go            # Vercel Go serverless function entry (package handler)
├── cmd/blackhat/             # Local server entry point
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

The app is structured for Vercel's Go runtime: `api/handler.go` declares `package handler` with an exported `Handler(w, r)`. `vercel.json` rewrites every route to the function, and `templates`, `static` and `i18n` are embedded into the binary so they survive the read-only serverless filesystem.

```bash
vercel link
vercel --prod
```

> **Note:** Vercel serverless functions only allow writes under `/tmp` and the
> platform caps request bodies (~4.5 MB). For full 50 MB uploads and the
> complete SAST toolchain, deploy the **Docker image** instead (Render,
> Fly.io, a VPS, or any container host). On serverless, tools installed by
> `build.sh` are not present in the runtime sandbox and are skipped gracefully.

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
