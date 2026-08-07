# Black Hat

A code analysis platform that detects security issues, performance problems, and code quality issues using trusted static analysis tools.

![Black Hat](https://img.shields.io/badge/Black_Hat-Code_Analysis-000000?style=for-the-badge&labelColor=000000&color=ffffff)
![Go](https://img.shields.io/badge/Go-1.21-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Fiber](https://img.shields.io/badge/Fiber-v2.52-000000?style=for-the-badge)

## Features

- **Security Analysis** - Scan projects for common security issues, exposed secrets, and known dependency vulnerabilities
- **Code Quality** - Identify maintainability issues, duplicated code, unused files, and coding best practices
- **Dependency Analysis** - Review third-party packages and detect publicly known vulnerabilities
- **Reports** - Export detailed reports in JSON and HTML formats
- **Multi-Language** - Support for 5 languages: English, Arabic, Russian, French, Spanish
- **RTL Support** - Full Right-to-Left layout support for Arabic
- **Premium Design** - Premium black-and-white aesthetic with smooth animations

## Analysis Tools

| Tool | Purpose |
|------|---------|
| Semgrep | Security scanning (XSS, SQL Injection, Command Injection, SSRF) |
| Trivy | Dependency vulnerabilities, Docker images, CVEs |
| Gitleaks | API Keys, AWS Keys, Tokens, Passwords |
| ESLint | JavaScript/TypeScript analysis |
| golangci-lint | Go analysis |
| Bandit | Python analysis |
| Clippy | Rust analysis |
| PMD | Java analysis |
| PHPStan | PHP analysis |

## Tech Stack

- **Backend:** Go (Golang) with Fiber framework
- **Frontend:** Go Templates + HTMX + Alpine.js
- **Styling:** Custom CSS (no frameworks)
- **Database:** PostgreSQL + Redis
- **Containerization:** Docker

## Quick Start

### Prerequisites

- Go 1.21+
- Docker (optional)
- PostgreSQL (optional)
- Redis (optional)

### Local Development

```bash
# Clone the repository
git clone https://github.com/i6gu1/Black-hat.git
cd Black-hat

# Install dependencies
go mod tidy

# Run the application
go run main.go
```

Visit `http://localhost:3000`

### Docker

```bash
# Build and run with Docker Compose
docker-compose up --build
```

### Environment Variables

```env
PORT=3000
ENV=production
DATABASE_URL=postgres://user:password@localhost:5432/blackhat?sslmode=disable
REDIS_URL=localhost:6379
MAX_UPLOAD_SIZE=52428800
UPLOAD_DIR=./uploads
ANALYSIS_TIMEOUT=600
MAX_CONCURRENT_ANALYSES=5

# AI-powered analysis (Gemini)
# Get a key from https://aistudio.google.com/apikey (AQ. prefixed keys)
# NEVER commit this file — .env.local is already gitignored.
AI_API_KEY=your_gemini_api_key
AI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
AI_MODEL=gemini-2.0-flash
```

> **Note:** Copy this block to a local `.env.local` file. The app reads it
> automatically on startup (`config.LoadEnvFile(".env.local")`). On Vercel,
> set the same variables in **Project Settings → Environment Variables**.
> The API key is never shipped in the image or the repo.

### AI Analysis

When `AI_API_KEY` is set, the AI model reads the extracted project files and
produces the full security report (vulnerabilities, quality issues, dependency
risks, and improvement suggestions). It first calls the OpenAI-compatible
endpoint and automatically falls back to Google's native `generateContent`
endpoint, which is the reliable transport for the newer `AQ.`-prefixed Gemini
keys.

## Project Structure

```
black-hat/
├── main.go                    # Application entry point
├── config/                    # Configuration loading
├── i18n/                      # Translation files (en, ar, ru, fr, es)
├── handlers/                  # HTTP handlers
├── models/                    # Data models
├── services/                  # Analysis services
├── database/                  # PostgreSQL & Redis
├── middleware/                 # HTTP middleware
├── templates/                 # HTML templates
├── static/                    # CSS, JS, images
└── uploads/                   # Temporary upload directory
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Home page |
| GET | `/upload` | Upload page |
| GET | `/results/:id` | Analysis results |
| GET | `/reports/:id` | Report download page |
| POST | `/api/upload` | Upload project for analysis |
| GET | `/api/analysis/status/:id` | Check analysis status |
| GET | `/api/results/security/:id` | Security findings |
| GET | `/api/results/quality/:id` | Quality findings |
| GET | `/api/results/dependencies/:id` | Dependency vulnerabilities |
| GET | `/api/reports/:id/:format` | Download report (json/html) |
| GET | `/health` | Health check |

## Supported Languages

| Language | Code | Direction | Default |
|----------|------|-----------|---------|
| English | en | LTR | Yes |
| Arabic | ar | RTL | No |
| Russian | ru | LTR | No |
| French | fr | LTR | No |
| Spanish | es | LTR | No |

## Deployment

### Vercel (Docker)

This project deploys to Vercel as a Docker container (see `Dockerfile.vercel`
and `vercel.json`).

```bash
# 1. Install the Vercel CLI (once)
npm i -g vercel

# 2. Log in and link the project to the existing Vercel project
vercel login
vercel link

# 3. Set environment variables in the dashboard OR via CLI:
vercel env add AI_API_KEY
vercel env add AI_BASE_URL
vercel env add AI_MODEL
# (repeat for production: vercel env add AI_API_KEY production)

# 4. Deploy a preview / production
vercel
vercel --prod
```

Every `git push` to the `main` branch also auto-redeploys the production
environment when the GitHub integration is enabled.

### Render.com

1. Connect your GitHub repository
2. Render will automatically detect the `render.yaml` configuration
3. Deploy with one click

### Docker

```bash
docker build -t black-hat .
docker run -p 3000:3000 black-hat
```

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
