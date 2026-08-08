# ---- Build stage ----
FROM golang:1.22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o black-hat ./cmd/api

# ---- Runtime stage ----
FROM alpine:latest

# Runtime dependencies: CA certs, curl/tar/git for build.sh, plus Python and
# Node so the pip/npm-based SAST tools (semgrep, bandit, njsscan, eslint) run.
RUN apk --no-cache add ca-certificates curl tar git bash \
    python3 py3-pip nodejs npm

WORKDIR /root/

# Install the SAST tools into /opt/bin (see build.sh). Best-effort: the app
# runs even if some tools fail to download.
COPY build.sh /build.sh
RUN bash /build.sh || true

COPY --from=builder /app/black-hat .

# Vercel Docker functions route traffic to port 80 by default (overridable via
# the PORT env var), so bind to 80; $PORT at runtime always wins.
ENV PORT=80

EXPOSE 80

CMD ["./black-hat"]
