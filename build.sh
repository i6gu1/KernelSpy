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
  fi
  chmod +x "$DEPCHECK_HOME/bin/dependency-check.sh" "$DEPCHECK_HOME/bin/dependency-check"
  # NOTE: do NOT symlink the launcher into $TOOLS_DIR — dependency-check.sh
  # locates its lib/ and data/ relative to its own path (dirname $0), so a
  # symlink would break it. findTool() finds it via DEPENDENCY_CHECK_HOME.
  rm -rf "$tmp"
  log "dependency-check installed at $DEPCHECK_HOME"
}

install_spotbugs() {
  # SpotBugs (Java security scanner) + the FindSecBugs plugin jar. Needs a JVM
  # at runtime and a JDK (javac) to compile the scanned sources — the runner
  # records a clear "missing" status when either is absent. The launcher is a
  # shell script that locates lib/ relative to its own path, so keep the whole
  # tree under SPOTBUGS_HOME and symlink the launcher into $TOOLS_DIR.
  if [ -x "$TOOLS_DIR/spotbugs" ]; then
    log "spotbugs already installed"
    return 0
  fi
  if ! command -v java >/dev/null 2>&1; then
    warn "java not available, skipping spotbugs (install openjdk-17-jre-headless)"
    return 1
  fi
  local prefix="${SPOTBUGS_HOME:-/opt/spotbugs}"
  local ver="${SPOTBUGS_VERSION:-4.9.1}"
  local url="https://github.com/spotbugs/spotbugs/releases/download/${ver}/spotbugs-${ver}.tgz"
  log "downloading spotbugs ${ver} from $url"
  local tmp
  tmp="$(mktemp -d)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp/sb.tgz" "$url" || { warn "failed to download spotbugs"; rm -rf "$tmp"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp/sb.tgz" "$url" || { warn "failed to download spotbugs"; rm -rf "$tmp"; return 1; }
  else
    warn "no curl/wget available, skipping spotbugs"
    rm -rf "$tmp"
    return 1
  fi
  tar -xzf "$tmp/sb.tgz" -C "$tmp" || { warn "failed to unpack spotbugs"; rm -rf "$tmp"; return 1; }
  rm -rf "$prefix"
  mkdir -p "$(dirname "$prefix")"
  if [ -d "$tmp/spotbugs-$ver" ]; then
    mv "$tmp/spotbugs-$ver" "$prefix"
  else
    warn "spotbugs-$ver dir not found inside archive"
    rm -rf "$tmp"
    return 1
  fi
  if [ -x "$prefix/bin/spotbugs" ]; then
    ln -sf "$prefix/bin/spotbugs" "$TOOLS_DIR/spotbugs"
  else
    warn "spotbugs launcher not found under $prefix/bin"
    rm -rf "$tmp"
    return 1
  fi

  # FindSecBugs plugin jar (Maven Central). The runner finds it via the
  # FINDSECBUGS_JAR env var or $TOOLS_DIR/findsecbugs-plugin.jar.
  local fsb="${FINDSECBUGS_JAR:-$TOOLS_DIR/findsecbugs-plugin.jar}"
  if [ ! -f "$fsb" ]; then
    local fsbver="${FINDSECBUGS_VERSION:-1.12.0}"
    log "downloading findsecbugs-plugin ${fsbver} from Maven Central"
    curl -fsSL -o "$fsb" "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${fsbver}/findsecbugs-plugin-${fsbver}.jar" \
      || { warn "failed to download findsecbugs plugin (set FINDSECBUGS_JAR to the jar path)"; rm -f "$fsb"; }
  fi
  rm -rf "$tmp"
  log "spotbugs installed at $prefix (launcher symlinked into $TOOLS_DIR)"
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

install_shellcheck() {
  # ShellCheck ships a single static binary as a .tar.xz on GitHub Releases.
  # Needs xz to unpack; skip gracefully when it is unavailable.
  if [ -x "$TOOLS_DIR/shellcheck" ]; then
    log "shellcheck already installed"
    return 0
  fi
  if ! command -v xz >/dev/null 2>&1; then
    warn "xz not available, skipping shellcheck (static binary is a .tar.xz)"
    return 1
  fi
  local ver="${SHELLCHECK_VERSION:-0.10.0}"
  local url="https://github.com/koalaman/shellcheck/releases/download/v${ver}/shellcheck-v${ver}.linux.${ARCH}.tar.xz"
  log "downloading shellcheck v${ver} from $url"
  local tmp
  tmp="$(mktemp -d)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp/sc.tar.xz" "$url" || { warn "failed to download shellcheck"; rm -rf "$tmp"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp/sc.tar.xz" "$url" || { warn "failed to download shellcheck"; rm -rf "$tmp"; return 1; }
  else
    warn "no curl/wget available, skipping shellcheck"
    rm -rf "$tmp"
    return 1
  fi
  tar -xJf "$tmp/sc.tar.xz" -C "$tmp" || { warn "failed to unpack shellcheck"; rm -rf "$tmp"; return 1; }
  local found
  found="$(find "$tmp" -type f -name shellcheck -perm -u+x | head -n1)"
  if [ -z "$found" ]; then
    warn "shellcheck binary not found inside archive"
    rm -rf "$tmp"
    return 1
  fi
  install -m 0755 "$found" "$TOOLS_DIR/shellcheck" || { warn "failed to install shellcheck"; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  log "shellcheck installed at $TOOLS_DIR/shellcheck"
}

install_cppcheck() {
  # Cppcheck has no official container image or portable release tarball, so
  # install it from the distro packages. Needs apt-get (Debian/Ubuntu) and
  # root in the build image.
  if [ -x "$TOOLS_DIR/cppcheck" ]; then
    log "cppcheck already installed"
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    warn "apt-get not available, skipping cppcheck"
    return 1
  fi
  if [ "$(id -u)" != "0" ] 2>/dev/null; then
    warn "not running as root, skipping cppcheck apt install"
    return 1
  fi
  log "installing cppcheck via apt-get"
  apt-get update -qq >/dev/null 2>&1 || { warn "apt-get update failed, skipping cppcheck"; return 1; }
  apt-get install -y -qq cppcheck >/dev/null 2>&1 || { warn "apt-get install cppcheck failed"; return 1; }
  if command -v cppcheck >/dev/null 2>&1; then
    ln -sf "$(command -v cppcheck)" "$TOOLS_DIR/cppcheck"
    log "cppcheck installed at $TOOLS_DIR/cppcheck"
  else
    warn "cppcheck binary not found after install"
    return 1
  fi
}

install_brakeman() {
  # Brakeman is a Ruby gem. Needs ruby/gem at runtime; guard on availability.
  if [ -x "$TOOLS_DIR/brakeman" ]; then
    log "brakeman already installed"
    return 0
  fi
  if ! command -v gem >/dev/null 2>&1; then
    warn "ruby/gem not available, skipping brakeman"
    return 1
  fi
  log "installing brakeman via gem"
  gem install --no-document brakeman >/dev/null 2>&1 || { warn "failed to gem install brakeman"; return 1; }
  if command -v brakeman >/dev/null 2>&1; then
    ln -sf "$(command -v brakeman)" "$TOOLS_DIR/brakeman"
    log "brakeman installed at $TOOLS_DIR/brakeman"
  else
    warn "brakeman binary not found after install"
    return 1
  fi
}

install_eslint() {
  # Debian's nodejs/npm packages ship a SYSTEM eslint (v6.4.0) that cannot
  # resolve npm-installed plugins (eslint-plugin-security needs eslint >= 8),
  # and the plain install_npm_tool short-circuits on that binary. Install
  # eslint@8 + the security plugins into a self-contained prefix (/opt/eslint)
  # that lives in the image, then symlink the v8 binary into $TOOLS_DIR so
  # findTool() picks it up before the system one. ESLINT_PREFIX is also baked
  # into the image so the Go runner can pass --resolve-plugins-relative-to.
  #
  # npm can transiently fail to reach the registry during cloud builds, so
  # retry the install a few times before giving up.
  local prefix="${ESLINT_PREFIX:-/opt/eslint}"
  # npm install --prefix (local style) puts the bin under node_modules/.bin;
  # the -g style puts it under prefix/bin. Check both for idempotency.
  local esbin=""
  for c in "$prefix/bin/eslint" "$prefix/node_modules/.bin/eslint"; do
    if [ -x "$c" ]; then
      esbin="$c"
      break
    fi
  done
  if [ -n "$esbin" ] && "$esbin" --version 2>/dev/null | grep -q '^v8'; then
    log "eslint@8 already installed at $prefix"
    return 0
  fi
  if ! command -v npm >/dev/null 2>&1; then
    warn "npm not available, skipping eslint"
    return 1
  fi
  mkdir -p "$prefix"
  local attempt
  for attempt in 1 2 3; do
    log "installing eslint@8 + security plugins into $prefix (attempt $attempt/3)"
    if npm install --prefix "$prefix" --no-audit --no-fund --silent \
        "eslint@8" "eslint-plugin-security" "eslint-plugin-no-secrets"; then
      break
    fi
    warn "npm install attempt $attempt failed; retrying..."
    sleep 5
  done
  # npm install --prefix puts the bin links under <prefix>/node_modules/.bin
  # (local-style install), not <prefix>/bin (that only happens with -g).
  esbin=""
  for c in "$prefix/bin/eslint" "$prefix/node_modules/.bin/eslint"; do
    if [ -x "$c" ]; then
      esbin="$c"
      break
    fi
  done
  if [ -z "$esbin" ]; then
    warn "eslint binary not found after install (checked $prefix/bin and $prefix/node_modules/.bin)"
    return 1
  fi
  ln -sf "$esbin" "$TOOLS_DIR/eslint"
  log "eslint symlinked into $TOOLS_DIR/eslint ($("$TOOLS_DIR/eslint" --version 2>/dev/null))"
}

detect_os_arch

# --- Standalone binaries (official GitHub releases) ---
GOSEC_VER="v2.21.4"
GITLEAKS_VER="v8.21.2"
TRIVY_VER="v0.73.0"

download_tarball "gosec" \
  "https://github.com/securego/gosec/releases/download/${GOSEC_VER}/gosec_${GOSEC_VER#v}_${OS}_${ARCH}.tar.gz" \
  "gosec" || true

# Gitleaks names its binaries with x64/arm64 (not amd64) since v8.16.
GITLEAKS_ARCH="$ARCH"
if [ "$ARCH" = "amd64" ]; then GITLEAKS_ARCH="x64"; fi
download_tarball "gitleaks" \
  "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_${OS}_${GITLEAKS_ARCH}.tar.gz" \
  "gitleaks" || true

# Trivy names its assets with capital "Linux-64bit" / "Linux-ARM64".
case "$OS/$ARCH" in
  linux/amd64)  TRIVY_ASSET="Linux-64bit" ;;
  linux/arm64)  TRIVY_ASSET="Linux-ARM64" ;;
  darwin/amd64) TRIVY_ASSET="macOS-64bit" ;;
  darwin/arm64) TRIVY_ASSET="macOS-ARM64" ;;
  *)            TRIVY_ASSET="Linux-64bit" ;;
esac
download_tarball "trivy" \
  "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VER}/trivy_${TRIVY_VER#v}_${TRIVY_ASSET}.tar.gz" \
  "trivy" || true

# --- Pre-download the Trivy vulnerability DB at build time ---
# The first scan on a cold serverless instance must not spend minutes
# downloading the ~150 MB vulnerability DB (the old default GCR mirror is
# being retired and often fails). Warming the cache into the image makes
# runtime scans start instantly. Best-effort: if this fails the first runtime
# scan retries the download via TRIVY_DB_REPOSITORY.
if [ -x "$TOOLS_DIR/trivy" ] && [ "${SAST_SKIP_TRIVY_DB:-}" != "1" ]; then
  TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/tmp/trivy-cache}"
  mkdir -p "$TRIVY_CACHE_DIR"
  log "pre-downloading trivy vulnerability DB into $TRIVY_CACHE_DIR (this can take a few minutes)"
  "$TOOLS_DIR/trivy" --cache-dir "$TRIVY_CACHE_DIR" image --download-db-only >/dev/null 2>&1 \
    || "$TOOLS_DIR/trivy" --cache-dir "$TRIVY_CACHE_DIR" --db-repository ghcr.io/aquasecurity/trivy-db image --download-db-only >/dev/null 2>&1 \
    || warn "trivy DB pre-download failed; the first runtime scan will download it via TRIVY_DB_REPOSITORY"
fi

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

# SpotBugs + FindSecBugs (Java security scanning; needs a JVM + JDK).
if [ "${SAST_SKIP_SPOTBUGS:-}" != "1" ]; then
  install_spotbugs || true
else
  warn "skipping spotbugs (SAST_SKIP_SPOTBUGS=1)"
fi

# --- New language coverage (best-effort) ---
if [ "${SAST_SKIP_SHELLCHECK:-}" != "1" ]; then
  install_shellcheck || true
else
  warn "skipping shellcheck (SAST_SKIP_SHELLCHECK=1)"
fi
if [ "${SAST_SKIP_CPPCHECK:-}" != "1" ]; then
  install_cppcheck || true
else
  warn "skipping cppcheck (SAST_SKIP_CPPCHECK=1)"
fi
if [ "${SAST_SKIP_BRAKEMAN:-}" != "1" ]; then
  install_brakeman || true
else
  warn "skipping brakeman (SAST_SKIP_BRAKEMAN=1)"
fi

# --- Python-based tools ---
install_python_tool "semgrep" || true
install_python_tool "bandit" || true
install_python_tool "njsscan" || true
if [ "${SAST_SKIP_CHECKOV:-}" != "1" ]; then
  install_python_tool "checkov" || true
else
  warn "skipping checkov (SAST_SKIP_CHECKOV=1)"
fi

# --- Node.js-based tools ---
install_eslint || true

log "build.sh finished. Tools installed under $TOOLS_DIR:"
ls -1 "$TOOLS_DIR" 2>/dev/null || true
log "CodeQL under $CODQL_HOME, Dependency-Check under $DEPCHECK_HOME"
