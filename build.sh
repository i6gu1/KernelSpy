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
# build continues. The pipeline gracefully reports "no findings" for any tool
# that is not installed.
#
# Usage:  SAST_TOOLS_DIR=/opt/bin bash build.sh
# =============================================================================
set -u

TOOLS_DIR="${SAST_TOOLS_DIR:-/opt/bin}"
mkdir -p "$TOOLS_DIR"

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

if [ "$OS" = "linux" ]; then
  download_tarball "gitleaks" \
    "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_linux_${ARCH}.tar.gz" \
    "gitleaks" || true
else
  download_tarball "gitleaks" \
    "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_${OS}_${ARCH}.tar.gz" \
    "gitleaks" || true
fi

download_tarball "trivy" \
  "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VER}/trivy_${TRIVY_VER#v}_${OS}-${ARCH}.tar.gz" \
  "trivy" || true

# --- Python-based tools ---
install_python_tool "semgrep" || true
install_python_tool "bandit" || true
install_python_tool "njsscan" || true

# --- Node.js-based tools ---
install_npm_tool "eslint" "eslint@8" "eslint-plugin-security" "eslint-plugin-no-secrets" || true

log "build.sh finished. Tools installed under $TOOLS_DIR:"
ls -1 "$TOOLS_DIR" 2>/dev/null || true
