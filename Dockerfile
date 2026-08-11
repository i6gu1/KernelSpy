# ---- Build stage ----
FROM golang:1.22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o black-hat ./cmd/api

# ---- Runtime stage ----
# Debian (glibc) is required: the CodeQL bundle ships glibc binaries and
# OWASP Dependency-Check needs a JVM, neither of which work on musl/alpine.
FROM debian:bookworm-slim

# Runtime dependencies: CA certs, curl/tar/unzip/git for build.sh, Python and
# Node for the pip/npm-based SAST tools, and a JVM for Dependency-Check.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tar unzip git bash \
    python3 python3-pip nodejs npm \
    openjdk-17-jre-headless \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /root/

# Install the SAST tools (see build.sh). Best-effort: the app runs even if
# some tools fail to download; failed tools are surfaced as "missing" in the
# report's Scanner Status section instead of silently producing false results.
COPY build.sh /build.sh
RUN bash /build.sh || true

COPY --from=builder /app/black-hat .

# Tool discovery + cache locations. TRIVY_CACHE_DIR and the Dependency-Check
# NVD data dir are mounted as volumes in docker-compose so the feeds survive
# container restarts.
ENV PORT=80 \
    SAST_TOOLS_DIR=/opt/bin \
    CODQL_HOME=/opt/codeql \
    DEPENDENCY_CHECK_HOME=/opt/dependency-check \
    TRIVY_CACHE_DIR=/opt/trivy-cache
RUN mkdir -p /opt/trivy-cache /opt/dependency-check/data

EXPOSE 80

CMD ["./black-hat"]
