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
```

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
- Instagram: [@izgu_](https://instagram.com/izgu_)
