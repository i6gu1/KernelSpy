#!/usr/bin/env bash
# =============================================================================
# build.sh — installs the industry-standard SAST tools used by the Go pipeline
#
# Vercel serverless runtimes cannot apt-get install packages at runtime, so the
# tools are provisioned here, during the build phase, into /opt/bin (override
# with SAST_TOOLS_DIR). The Go backend locates them via findTool() which checks
# /opt/bin first, then PATH.
#
# Every step is best-effort: a failure to fetch one tool logs a warning and the
# build continues. The pipeline now RECORDS a per-tool status in the report, so
# a tool that failed to install shows up as "missing" instead of silently
# producing a false "clean" report.
#
# Usage:  SAST_TOOLS_DIR=/opt/bin bash build.sh
# =============================================================================
set -u

TOOLS_DIR="${SAST_TOOLS_DIR:-/opt/bin}"
CODQL_HOME="${CODQL_HOME:-/opt/codeql}"
DEPCHECK_HOME="${DEPENDENCY_CHECK_HOME:-/opt/dependency-check}"
mkdir -p "$TOOLS_DIR" "$CODQL_HOME" "$DEPCHECK_HOME"

log()  { echo "[build.sh] $*"; }
warn() { echo "[build.sh] WARN: $*"; }

detect_os_arch() {
  case "$(uname -s)" in
    Linux*)  OS=linux ;;
    Darwin*) OS=darwin ;;
    *)       OS=linux ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *)            ARCH=amd64 ;;
  esac
  log "target: ${OS}/${ARCH}"
}

download_tarball() {
  # download_tarball <name> <url> <expected-binary-name>
  local name="$1" url="$2" bin="$3"
  if [ -x "$TOOLS_DIR/$bin" ]; then
    log "$name already installed at $TOOLS_DIR/$bin"
    return 0
  fi
  log "downloading $name from $url"
  local tmp
  tmp="$(mktemp -d)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp/dl.tgz" "$url" || { warn "failed to download $name"; rm -rf "$tmp"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp/dl.tgz" "$url" || { warn "failed to download $name"; rm -rf "$tmp"; return 1; }
  else
    warn "no curl/wget available, skipping $name"
    rm -rf "$tmp"
    return 1
  fi
  tar -xzf "$tmp/dl.tgz" -C "$tmp" || { warn "failed to unpack $name"; rm -rf "$tmp"; return 1; }
  local found
  found="$(find "$tmp" -type f -name "$bin" -perm -u+x | head -n1)"
  if [ -z "$found" ]; then
    found="$(find "$tmp" -type f -name "$bin" | head -n1)"
  fi
  if [ -z "$found" ]; then
    warn "binary '$bin' not found inside $name archive"
    rm -rf "$tmp"
    return 1
  fi
  install -m 0755 "$found" "$TOOLS_DIR/$bin" || { warn "failed to install $bin"; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  log "$name installed at $TOOLS_DIR/$bin"
}

install_codeql() {
  # CodeQL must be extracted as a whole tree (binary + extractors + query
  # packs), so it gets its own function. The full bundle is ~1.5 GB.
  if [ -x "$CODQL_HOME/codeql/codeql" ]; then
    log "codeql already installed at $CODQL_HOME"
    return 0
  fi
  local url="https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.20.0/codeql-bundle-linux64.tar.gz"
  if [ "${CODQL_BUNDLE_URL:-}" != "" ]; then
    url="$CODQL_BUNDLE_URL"
  fi
  log "downloading codeql bundle from $url (large download, this can take a while)"
  local tmp
  tmp="$(mktemp -d)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp/codeql.tgz" "$url" || { warn "failed to download codeql bundle"; rm -rf "$tmp"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp/codeql.tgz" "$url" || { warn "failed to download codeql bundle"; rm -rf "$tmp"; return 1; }
  else
    warn "no curl/wget available, skipping codeql"
    rm -rf "$tmp"
    return 1
  fi
  tar -xzf "$tmp/codeql.tgz" -C "$tmp" || { warn "failed to unpack codeql bundle"; rm -rf "$tmp"; return 1; }
  local found
  found="$(find "$tmp" -type f -path '*/codeql/codeql' -perm -u+x | head -n1)"
  if [ -z "$found" ]; then
    warn "codeql binary not found inside bundle"
    rm -rf "$tmp"
    return 1
  fi
  rm -rf "$CODQL_HOME"/*
  tar -xzf "$tmp/codeql.tgz" -C "$CODQL_HOME" --strip-components=1 || { warn "failed to install codeql tree"; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  log "codeql installed at $CODQL_HOME (binary: $CODQL_HOME/codeql/codeql)"
}

install_depcheck() {
  # OWASP Dependency-Check: a Java application distributed as a zip. Keep the
  # whole tree so its launcher finds its lib/ and data/ dirs, and symlink the
  # launcher into TOOLS_DIR so findTool() picks it up from the PATH too.
  if [ -x "$DEPCHECK_HOME/bin/dependency-check.sh" ]; then
    log "dependency-check already installed at $DEPCHECK_HOME"
    return 0
  fi
  local ver="9.2.1"
  if [ "${DEPCHECK_VERSION:-}" != "" ]; then
    ver="$DEPCHECK_VERSION"
  fi
  local url="https://github.com/dependency-check/DependencyCheck/releases/download/v${ver}/dependency-check-${ver}-release.zip"
  log "downloading dependency-check v${ver} from $url"
  local tmp
  tmp="$(mktemp -d)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp/dc.zip" "$url" || { warn "failed to download dependency-check"; rm -rf "$tmp"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp/dc.zip" "$url" || { warn "failed to download dependency-check"; rm -rf "$tmp"; return 1; }
  else
    warn "no curl/wget available, skipping dependency-check"
    rm -rf "$tmp"
    return 1
  fi
  if ! command -v unzip >/dev/null 2>&1; then
    warn "unzip not available, skipping dependency-check"
    rm -rf "$tmp"
    return 1
  fi
  unzip -q "$tmp/dc.zip" -d "$tmp" || { warn "failed to unpack dependency-check"; rm -rf "$tmp"; return 1; }
  local found
  found="$(find "$tmp" -type f -name dependency-check.sh | head -n1)"
  if [ -z "$found" ]; then
    warn "dependency-check.sh not found inside archive"
    rm -rf "$tmp"
    return 1
  fi
  rm -rf "$DEPCHECK_HOME"/*
  unzip -q "$tmp/dc.zip" -d "$(dirname "$DEPCHECK_HOME")"
  # The zip contains a top-level dir like dependency-check-9.2.1/; normalize it.
  if [ -d "$(dirname "$DEPCHECK_HOME")/dependency-check-$ver" ] && [ "$DEPCHECK_HOME" != "$(dirname "$DEPCHECK_HOME")/dependency-check-$ver" ]; then
    rm -rf "$DEPCHECK_HOME"
    mv "$(dirname "$DEPCHECK_HOME")/dependency-check-$ver" "$DEPCHECK_HOME"
  fi	chmod +x "$DEPCHECK_HOME/bin/dependency-check.sh" "$DEPCHECK_HOME/bin/dependency-check"
	# NOTE: do NOT symlink the launcher into $TOOLS_DIR — dependency-check.sh
	# locates its lib/ and data/ relative to its own path (dirname $0), so a
	# symlink would break it. findTool() finds it via DEPENDENCY_CHECK_HOME.
	rm -rf "$tmp"
	log "dependency-check installed at $DEPCHECK_HOME"
}

install_python_tool() {
  # install_python_tool <name>
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    log "$name already available"
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not available, skipping $name"
    return 1
  fi
  log "installing $name via pip"
  python3 -m pip install --quiet --break-system-packages "$name" 2>/dev/null \
    || python3 -m pip install --quiet "$name" 2>/dev/null \
    || { warn "failed to pip install $name"; return 1; }
  log "$name installed"
}

install_npm_tool() {
  # install_npm_tool <name> [extra...]
  local name="$1"; shift
  if command -v "$name" >/dev/null 2>&1; then
    log "$name already available"
    return 0
  fi
  if ! command -v npm >/dev/null 2>&1; then
    warn "npm not available, skipping $name"
    return 1
  fi
  log "installing $name via npm"
  npm install -g --silent "$@" || { warn "failed to npm install $name"; return 1; }
  log "$name installed"
}

detect_os_arch

# --- Standalone binaries (official GitHub releases) ---
GOSEC_VER="v2.21.4"
GITLEAKS_VER="v8.21.2"
TRIVY_VER="v0.56.2"

download_tarball "gosec" \
  "https://github.com/securego/gosec/releases/download/${GOSEC_VER}/gosec_${GOSEC_VER#v}_${OS}_${ARCH}.tar.gz" \
  "gosec" || true

download_tarball "gitleaks" \
  "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_${OS}_${ARCH}.tar.gz" \
  "gitleaks" || true

download_tarball "trivy" \
  "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VER}/trivy_${TRIVY_VER#v}_${OS}-${ARCH}.tar.gz" \
  "trivy" || true

# --- Enterprise tools ---
# CodeQL: full bundle (includes the codeql/<lang>-queries packs). Linux/glibc
# only — the Docker image must be glibc-based (debian), not alpine.
if [ "$OS" = "linux" ] && [ "${SAST_SKIP_CODQL:-}" != "1" ]; then
  install_codeql || true
else
  warn "skipping codeql (non-linux host or SAST_SKIP_CODQL=1)"
fi

# OWASP Dependency-Check: needs a JVM at runtime (openjdk-17-jre-headless in
# the Docker image).
if [ "${SAST_SKIP_DEPCHECK:-}" != "1" ]; then
  install_depcheck || true
else
  warn "skipping dependency-check (SAST_SKIP_DEPCHECK=1)"
fi

# --- Python-based tools ---
install_python_tool "semgrep" || true
install_python_tool "bandit" || true
install_python_tool "njsscan" || true

# --- Node.js-based tools ---
install_npm_tool "eslint" "eslint@8" "eslint-plugin-security" "eslint-plugin-no-secrets" || true

log "build.sh finished. Tools installed under $TOOLS_DIR:"
ls -1 "$TOOLS_DIR" 2>/dev/null || true
log "CodeQL under $CODQL_HOME, Dependency-Check under $DEPCHECK_HOME"
