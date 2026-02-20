#!/usr/bin/env bash
# =============================================================================
#  Rec0n-Zer0 — Automated Penetration Testing Recon Suite
#
#  Why we built this:
#    Because manually running 20 tools in sequence is not security consulting,
#    it's busywork. Rec0n-Zer0 chains the best open-source recon tools into a
#    single automated workflow so you spend your time on analysis and reporting
#    — not copy-pasting commands.
#
#  Credits:
#    ProjectDiscovery (https://projectdiscovery.io)
#      — subfinder, dnsx, naabu, httpx, katana, nuclei, and more.
#        The majority of the heavy lifting in this suite is powered by their
#        incredible open-source toolchain. Go support their work.
#
#    Claude AI (https://claude.ai)
#      — AI pair-programmer that wrote and refined this suite.
#        The lazy consultant's secret weapon.
#
#  For authorized security engagements only.
#  Designed for Kali Linux.
# =============================================================================

set -euo pipefail

# ── Script location — tools always install relative to this file ──────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/Rec0n-Zer0-Tools"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  MAGENTA='\033[0;35m'
BOLD='\033[1m';    DIM='\033[2m';      NC='\033[0m'

# ── Spinner PID tracker — updated by run(); read by _cleanup() ────────────────
_SPINNER_PID=""

_cleanup() {
  [ -n "$_SPINNER_PID" ] && kill "$_SPINNER_PID" 2>/dev/null || true
  tput cnorm 2>/dev/null || true   # always restore cursor
  printf "\r\033[K"                # clear any partial spinner line
  [ -n "$LOCK_FILE" ] && rm -f "$LOCK_FILE" 2>/dev/null || true
}
trap _cleanup EXIT INT TERM

# ── Globals ───────────────────────────────────────────────────────────────────
DOMAIN=""
OUTPUT_DIR=""
LOG_FILE=""
WORDLIST="${WORDLIST:-}"
CURRENT_PROFILE="standard"
TOOL_TIMEOUT="${TOOL_TIMEOUT:-300}"   # seconds per tool; override: TOOL_TIMEOUT=600 ./Rec0n-Zer0.sh
THREADS="${THREADS:-50}"              # concurrency for httpx/ffuf/gobuster etc; override: THREADS=100 ./Rec0n-Zer0.sh
LOCK_FILE=""                          # set dynamically in setup() — used to prevent duplicate runs
SCAN_START=0                          # set in setup() — used to compute total elapsed time in summary
RECON_VENV="$TOOLS_DIR/venv"   # Python venv — lives in Rec0n-Zer0-Tools/ next to the script

# =============================================================================
#  TOOL TOGGLES  (1 = enabled, 0 = disabled)
#  Override at runtime:  ENABLE_AMASS=0 ./Rec0n-Zer0.sh example.com
# =============================================================================

# — Subdomain Enumeration —
ENABLE_SUBFINDER=1
ENABLE_AMASS=1
ENABLE_ASSETFINDER=1
ENABLE_FINDOMAIN=1

# — DNS —
ENABLE_DNSX=1
ENABLE_DNSRECON=1
ENABLE_NMAP_DNS=1
ENABLE_DIG=1

# — Port Scanning —
ENABLE_NAABU=1
ENABLE_NMAP=1
ENABLE_MASSCAN=0      # needs root

# — HTTP —
ENABLE_HTTPX=1
ENABLE_WAFW00F=1

# — Content Discovery —
ENABLE_FFUF=1
ENABLE_GOBUSTER=1
ENABLE_FEROXBUSTER=1
ENABLE_DIRSEARCH=0

# — URL Discovery —
ENABLE_WAYBACKURLS=1
ENABLE_GAU=1
ENABLE_KATANA=1
ENABLE_GOSPIDER=0
ENABLE_GF=1

# — Vulnerability Scanning —
ENABLE_NUCLEI=1
ENABLE_NIKTO=0        # slow, opt-in

# — Screenshots —
ENABLE_GOWITNESS=1
ENABLE_AQUATONE=0

# — Secrets —
ENABLE_TRUFFLEHOG=0
ENABLE_GITLEAKS=1

# =============================================================================
#  API KEYS  (all optional — tools run without them, keys improve coverage)
#  Stored in: ~/.config/recon/api_keys.conf
#  Override at runtime:  API_SHODAN=abc123 ./Rec0n-Zer0.sh example.com
# =============================================================================
RECON_API_CONFIG="${HOME}/.config/recon/api_keys.conf"

API_SHODAN=""          # Shodan                          → subfinder, findomain
API_GITHUB=""          # GitHub token                    → subfinder
API_VIRUSTOTAL=""      # VirusTotal                      → subfinder, findomain
API_SECURITYTRAILS=""  # SecurityTrails                  → subfinder
API_CENSYS_ID=""       # Censys API ID                   → subfinder
API_CENSYS_SECRET=""   # Censys API Secret               → subfinder
API_OTX=""             # AlienVault OTX                  → gau

# =============================================================================
#  DEPENDENCY INSTALLATION REGISTRY
# =============================================================================
# Format: "binary:method:value"
# Methods:
#   system  — use the OS package manager (apt / dnf / yum)
#             value is the package name; special names resolved per-distro
#   go      — go install -v <value>  (binary lands in Rec0n-Zer0-Tools/go/bin/)
#   pip     — pip install inside venv (Rec0n-Zer0-Tools/venv/)
DEPS=(
  # Subdomain Enumeration
  "subfinder:go:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "amass:system:amass"
  "assetfinder:go:github.com/tomnomnom/assetfinder@latest"
  "findomain:system:findomain"
  # DNS
  "dnsx:go:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "dnsrecon:pip:dnsrecon"
  "dig:system:dig"
  "nmap:system:nmap"
  # Port Scanning
  "naabu:go:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "masscan:system:masscan"
  # HTTP Probing
  "httpx:go:github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "wafw00f:pip:wafw00f"
  # Content Discovery
  "ffuf:system:ffuf"
  "gobuster:system:gobuster"
  "feroxbuster:system:feroxbuster"
  "dirsearch:system:dirsearch"
  # URL Discovery
  "waybackurls:go:github.com/tomnomnom/waybackurls@latest"
  "gau:go:github.com/lc/gau/v2/cmd/gau@latest"
  "katana:go:github.com/projectdiscovery/katana/cmd/katana@latest"
  "gospider:go:github.com/jaeles-project/gospider@latest"
  "gf:go:github.com/tomnomnom/gf@latest"
  # Vulnerability Scanning
  "nuclei:go:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "nikto:system:nikto"
  # Screenshots
  "gowitness:go:github.com/sensepost/gowitness/v3@latest"
  # Secret Scanning
  "trufflehog:system:trufflehog"
  "gitleaks:system:gitleaks"
)

# =============================================================================
#  HELPER FUNCTIONS
# =============================================================================

banner() {
  clear
  echo -e "${CYAN}${BOLD}"
  echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
  echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
  echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
  echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
  echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
  echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
  echo ""
  echo "  ███████╗ ███████╗ ██████╗   ██████╗ "
  echo "  ╚════██║ ██╔════╝ ██╔══██╗ ██╔═══██╗"
  echo "      ██╔╝ █████╗   ██████╔╝ ██║   ██║"
  echo "    ██╔╝   ██╔══╝   ██╔══██╗ ██║   ██║"
  echo "  ███████╗ ███████╗ ██║  ██║ ╚██████╔╝"
  echo "  ╚══════╝ ╚══════╝ ╚═╝  ╚═╝  ╚═════╝ "
  echo -e "${NC}"
  echo -e "${YELLOW}  Rec0n-Zer0 — Automated Penetration Testing Recon Suite${NC}"
  echo -e "${DIM}  Automate the boring. Focus on what matters.${NC}"
  echo ""
  echo -e "${DIM}  Powered by ProjectDiscovery tools  |  Coded by Claude AI${NC}"
  echo -e "${DIM}  For authorized engagements only.${NC}"
  echo ""
}

section() {
  echo ""
  echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════╗${NC}"
  printf "${BOLD}${MAGENTA}║  %-44s║${NC}\n" "$1"
  echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════╝${NC}"
}

info()     { echo -e "${BLUE}[*]${NC} $*"; }
ok()       { echo -e "${GREEN}[+]${NC} $*"; }
warn()     { echo -e "${YELLOW}[!]${NC} $*"; }
err()      { echo -e "${RED}[-]${NC} $*"; }
cmd_echo() { echo -e "    ${CYAN}→${NC} $*"; }

# Check if binary exists
has() { command -v "$1" &>/dev/null; }

# Check if a tool is both ENABLED by user AND installed
use() {
  local tool="$1"
  local varname="ENABLE_$(echo "$tool" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  local enabled="${!varname:-1}"
  [ "$enabled" -eq 0 ] && return 1
  # Map logical tool names to actual binary names where they differ
  local binary; binary=$(_binary_name "$tool")
  if ! has "$binary"; then
    warn "${tool} not installed — skipping"
    return 1
  fi
  return 0
}

# Toggle a tool on/off
toggle_tool() {
  local tool="$1"
  local varname="ENABLE_$(echo "$tool" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  local current="${!varname:-1}"
  if [ "$current" -eq 1 ]; then
    printf -v "$varname" '%s' "0"
  else
    printf -v "$varname" '%s' "1"
  fi
}

# Print coloured ON/OFF badge
status_badge() {
  local varname="ENABLE_$(echo "$1" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  local enabled="${!varname:-1}"
  if [ "$enabled" -eq 1 ]; then
    printf "${GREEN}[ON ]${NC}"
  else
    printf "${RED}[OFF]${NC}"
  fi
}

# Resolve a logical tool name to its actual binary name
_binary_name() {
  case "$1" in
    nmap_dns) echo "nmap" ;;
    *)        echo "$1"   ;;
  esac
}

# Print installed/missing badge
install_badge() {
  local bin; bin=$(_binary_name "$1")
  has "$bin" && printf "${GREEN}installed${NC}" || printf "${DIM}not found${NC}"
}

# =============================================================================
#  OS / PACKAGE MANAGER DETECTION
# =============================================================================

# PKG_MGR is set once and reused by check_python3_env() and install_deps()
PKG_MGR=""

detect_pkg_manager() {
  local os_type
  os_type=$(uname -s) || true
  case "$os_type" in
    Linux)
      if has apt-get; then
        PKG_MGR="apt"
      elif has dnf; then
        PKG_MGR="dnf"
      elif has yum; then
        PKG_MGR="yum"
      else
        err "No supported package manager found (apt / dnf / yum)."
        return 1
      fi
      ok "OS: Linux  |  package manager: $PKG_MGR"
      ;;
    *)
      err "Unsupported OS: $os_type. This tool is designed for Kali Linux."
      return 1
      ;;
  esac
}

# pkg_install <package> — install a single package via the detected manager
# Handles distro-specific package name differences for certain tools.
pkg_install() {
  local pkg="$1"
  # Resolve distro-specific package names
  case "$pkg" in
    dig)
      case "$PKG_MGR" in
        apt)      pkg="dnsutils" ;;
        dnf|yum)  pkg="bind-utils" ;;
      esac
      ;;
  esac
  case "$PKG_MGR" in
    apt)  $SUDO apt-get install -y "$pkg" 2>&1 | tail -5 ;;
    dnf)  $SUDO dnf install -y "$pkg" 2>&1 | tail -5 ;;
    yum)  $SUDO yum install -y "$pkg" 2>&1 | tail -5 ;;
  esac
}

# =============================================================================
#  PYTHON 3 ENVIRONMENT CHECK
# =============================================================================

check_python3_env() {
  section "Python 3 Environment"

  [ -z "$PKG_MGR" ] && detect_pkg_manager

  local SUDO=""
  [ "$(id -u)" -ne 0 ] && SUDO="sudo"

  # ── 1. Verify python3 ─────────────────────────────────────────────────────
  if ! has python3; then
    warn "python3 not found — installing..."
    case "$PKG_MGR" in
      apt)  $SUDO apt-get install -y python3 python3-pip ;;
      dnf)  $SUDO dnf install -y python3 python3-pip ;;
      yum)  $SUDO yum install -y python3 python3-pip ;;
    esac || { err "Failed to install python3."; return 1; }
  fi
  ok "python3 : $(python3 --version 2>&1)"

  # ── 2. Verify pip3 ────────────────────────────────────────────────────────
  if ! has pip3; then
    warn "pip3 not found — bootstrapping via ensurepip..."
    python3 -m ensurepip --upgrade 2>/dev/null || true
    if ! has pip3; then
      # Last resort: install python3-pip via package manager
      case "$PKG_MGR" in
        apt) $SUDO apt-get install -y python3-pip 2>/dev/null || true ;;
        dnf) $SUDO dnf install -y python3-pip 2>/dev/null || true ;;
        yum) $SUDO yum install -y python3-pip 2>/dev/null || true ;;
      esac
    fi
    if ! has pip3; then
      err "pip3 still not available. Install python3-pip manually."
      return 1
    fi
  fi
  ok "pip3    : $(pip3 --version 2>&1)"

  # ── 3. Warn if 'python' resolves to python2 ───────────────────────────────
  if has python; then
    local py_major
    py_major=$(python --version 2>&1 | grep -o '[0-9]' | head -1) || true
    if [ "$py_major" = "2" ]; then
      warn "'python' points to Python 2. This script always uses 'python3' explicitly."
      warn "To alias: add 'alias python=python3' to your shell rc file."
    fi
  fi

  # ── 4. Set up Python virtual environment (isolates pip tools from system Python) ──
  setup_python_venv || true

  # ── 5. Add Go bin to PATH ─────────────────────────────────────────────────
  local go_bin="$TOOLS_DIR/go/bin"
  if [ -d "$go_bin" ] && [[ ":$PATH:" != *":$go_bin:"* ]]; then
    export PATH="$go_bin:$PATH"
    ok "Added Go bin to PATH: $go_bin"
  elif [ -d "$go_bin" ]; then
    ok "Go bin already in PATH: $go_bin"
  else
    warn "$go_bin does not exist yet — created after first 'go install'"
  fi

  ok "Python 3 environment check complete."
}

# =============================================================================
#  PYTHON VIRTUAL ENVIRONMENT
# =============================================================================

setup_python_venv() {
  local SUDO=""
  [ "$(id -u)" -ne 0 ] && SUDO="sudo"

  # ── Ensure python3-venv package is available ───────────────────────────────
  if ! python3 -c "import venv" 2>/dev/null; then
    warn "python3 venv module not found — installing python3-venv..."
    case "${PKG_MGR:-apt}" in
      apt)  $SUDO apt-get install -y python3-venv 2>/dev/null || true ;;
      dnf)  $SUDO dnf install -y python3-venv 2>/dev/null || true ;;
      yum)  $SUDO yum install -y python3-venv 2>/dev/null || true ;;
    esac
    if ! python3 -c "import venv" 2>/dev/null; then
      err "Cannot create Python venv — python3-venv unavailable."
      return 1
    fi
  fi

  # ── Create venv if it doesn't exist ───────────────────────────────────────
  if [ ! -d "$RECON_VENV" ]; then
    mkdir -p "$(dirname "$RECON_VENV")"
    python3 -m venv "$RECON_VENV" || {
      err "Failed to create Python venv at $RECON_VENV"
      return 1
    }
    ok "Python venv created  → $RECON_VENV"
    "$RECON_VENV/bin/pip" install --quiet --upgrade pip 2>/dev/null || true
  else
    ok "Python venv exists   → $RECON_VENV"
  fi

  # ── Add venv bin to PATH ───────────────────────────────────────────────────
  local venv_bin="$RECON_VENV/bin"
  if [[ ":$PATH:" != *":$venv_bin:"* ]]; then
    export PATH="$venv_bin:$PATH"
    ok "Added venv to PATH   : $venv_bin"
  fi
}

# =============================================================================
#  DEPENDENCY INSTALLATION
# =============================================================================

install_deps() {
  section "Dependency Installation"
  info "Checking and installing all required tools..."
  echo ""

  # ── 0. Disk space check (Go compilation needs ~2 GB free) ─────────────────
  # -P (POSIX) prevents line-wrapping for long device names
  local _avail_kb _avail_mb
  _avail_kb=$(df -Pk "$SCRIPT_DIR" 2>/dev/null | awk 'NR==2 {print $4}') || _avail_kb=0
  _avail_mb=$(( _avail_kb / 1024 ))
  if [ "$_avail_mb" -lt 2000 ]; then
    warn "Low disk space: ${_avail_mb}MB free on $SCRIPT_DIR (Go builds need ~2 GB)"
    warn "Large tools (naabu, nuclei) may fail to compile."
    warn "Free up space or run: go clean -cache && go clean -modcache"
  else
    ok "Disk space: ${_avail_mb}MB free on $SCRIPT_DIR"
  fi

  # ── 1. Detect OS and package manager ──────────────────────────────────────
  detect_pkg_manager || return 1

  # ── 2. Set sudo prefix ────────────────────────────────────────────────────
  local SUDO=""
  [ "$(id -u)" -ne 0 ] && SUDO="sudo"

  # ── 3. Update package index ───────────────────────────────────────────────
  if [ "$PKG_MGR" = "apt" ]; then
    info "Updating apt package index..."
    $SUDO apt-get update -qq 2>/dev/null || true
  fi

  # ── 4. Install Go ─────────────────────────────────────────────────────────
  if ! has go; then
    info "Go not found — installing..."
    case "$PKG_MGR" in
      apt)  $SUDO apt-get install -y golang-go ;;
      dnf)  $SUDO dnf install -y golang ;;
      yum)  $SUDO yum install -y golang ;;
    esac || { err "Failed to install Go."; return 1; }
    ok "Go installed."
  else
    ok "Go       : $(go version 2>/dev/null)"
  fi

  # ── 5. Python 3 & pip3 ────────────────────────────────────────────────────
  check_python3_env

  # ── 6. Set GOPATH/GOBIN into tools directory and add Go bin to PATH ────────
  # GOBIN takes precedence over GOPATH/bin — set both to be explicit.
  export GOPATH="$TOOLS_DIR/go"
  export GOBIN="$TOOLS_DIR/go/bin"
  local go_bin="$GOBIN"
  mkdir -p "$go_bin" 2>/dev/null || true          # create early so PATH is always valid
  [[ ":$PATH:" != *":$go_bin:"* ]] && export PATH="$go_bin:$PATH"
  ok "GOPATH → $GOPATH"
  ok "GOBIN  → $GOBIN"

  # ── 6a. Fix Go module proxy DNS (some VM/VPN environments block it) ─────────
  #  Symptom: "lookup proxy.golang.org: no such host" during go install
  #  Fix: prepend 8.8.8.8 to /etc/resolv.conf so Go's resolver can reach the proxy
  if ! getent hosts proxy.golang.org >/dev/null 2>&1; then
    warn "Go module proxy DNS unreachable — adding 8.8.8.8 as fallback nameserver..."
    if ! grep -q 'nameserver 8.8.8.8' /etc/resolv.conf 2>/dev/null; then
      local _resolv_tmp; _resolv_tmp=$(mktemp)
      { echo "nameserver 8.8.8.8"; cat /etc/resolv.conf; } > "$_resolv_tmp" \
        && mv "$_resolv_tmp" /etc/resolv.conf \
        && ok "Added nameserver 8.8.8.8 to /etc/resolv.conf" \
        || warn "Could not update /etc/resolv.conf — go install may fail for some modules"
    else
      ok "8.8.8.8 already in /etc/resolv.conf"
    fi
  else
    ok "Go module proxy DNS  : OK"
  fi

  # ── 6b. Install CGO build dependencies (needed by naabu / gopacket) ────────
  info "Installing CGO build dependencies (libpcap-dev for naabu)..."
  case "$PKG_MGR" in
    apt)  $SUDO apt-get install -y libpcap-dev 2>/dev/null | tail -2 || true ;;
    dnf)  $SUDO dnf install -y libpcap-devel 2>/dev/null | tail -2 || true ;;
    yum)  $SUDO yum install -y libpcap-devel 2>/dev/null | tail -2 || true ;;
  esac

  # ── 7. Install each tool ──────────────────────────────────────────────────
  local installed_count=0
  local skipped_count=0
  local failed_count=0
  local failed_tools=()

  echo ""
  info "Scanning ${#DEPS[@]} tool dependencies..."
  echo ""

  for dep in "${DEPS[@]}"; do
    local tool="${dep%%:*}"
    local remainder="${dep#*:}"
    local method="${remainder%%:*}"
    local value="${remainder#*:}"

    # For go tools check TOOLS_DIR directly — has() finds system-wide versions
    # in /usr/bin and would incorrectly mark them as already installed.
    local already_installed=0
    case "$method" in
      go)   [ -x "$TOOLS_DIR/go/bin/$tool" ] && already_installed=1 ;;
      *)    has "$tool"                        && already_installed=1 ;;
    esac

    if [ "$already_installed" -eq 1 ]; then
      local tool_path
      case "$method" in
        go) tool_path="$TOOLS_DIR/go/bin/$tool" ;;
        *)  tool_path="$(command -v "$tool")" ;;
      esac
      printf "  ${GREEN}[OK ]${NC}  %-18s already installed → %s\n" "$tool" "$tool_path"
      skipped_count=$((skipped_count + 1))
      continue
    fi

    # Not installed — attempt installation
    printf "  ${YELLOW}[...]${NC}  %-18s installing via %s...\n" "$tool" "$method"

    local install_ok=1
    case "$method" in
      system)
        pkg_install "$value" || install_ok=0
        ;;
      go)
        # GONOSUMDB=* skips sum.golang.org if DNS is still unreliable after the 6a fix
        # GOPROXY falls back to direct if the proxy is unreachable
        # GOBIN set inline as a safety net in case env was altered
        GOPROXY=https://proxy.golang.org,direct GONOSUMDB='*' \
          GOPATH="$TOOLS_DIR/go" GOBIN="$TOOLS_DIR/go/bin" \
          go install -v "$value" 2>&1 | tail -3 || install_ok=0
        ;;
      pip)
        "$RECON_VENV/bin/pip" install --quiet "$value" 2>&1 | tail -3 || install_ok=0
        ;;
      *)
        warn "Unknown method '$method' for $tool — skipping"
        install_ok=0
        ;;
    esac

    # Verify the binary landed where expected
    local verify_ok=0
    case "$method" in
      go) [ -x "$TOOLS_DIR/go/bin/$tool" ] && verify_ok=1 ;;
      *)  has "$tool"                        && verify_ok=1 ;;
    esac

    if [ "$install_ok" -eq 1 ] && [ "$verify_ok" -eq 1 ]; then
      printf "  ${GREEN}[DONE]${NC} %-18s installed successfully\n" "$tool"
      installed_count=$((installed_count + 1))
    else
      printf "  ${RED}[FAIL]${NC} %-18s installation failed\n" "$tool"
      failed_tools+=("$tool")
      failed_count=$((failed_count + 1))
    fi
  done

  # ── 8. Summary ────────────────────────────────────────────────────────────
  echo ""
  echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
  echo -e "${BOLD}${CYAN}│  Dependency Installation Summary                         │${NC}"
  echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
  echo ""
  ok "Already installed : $skipped_count"
  ok "Newly installed   : $installed_count"
  if [ "$failed_count" -gt 0 ]; then
    err "Failed            : $failed_count"
    err "Failed tools      : ${failed_tools[*]}"
    warn "Some tools may not be in your distro's repos — install them manually."
  else
    ok "All dependencies satisfied."
  fi

  # ── 9. PATH persistence hint ──────────────────────────────────────────────
  local shell_rc
  case "${SHELL:-}" in
    */zsh)  shell_rc="~/.zshrc" ;;
    */bash) shell_rc="~/.bashrc" ;;
    *)      shell_rc="~/.profile" ;;
  esac
  echo ""
  info "To persist PATH changes across sessions, add to $shell_rc:"
  echo ""
  echo "    export PATH=\"$TOOLS_DIR/go/bin:\$PATH\""
  echo "    export PATH=\"$TOOLS_DIR/venv/bin:\$PATH\""
  echo ""
}

# =============================================================================
#  DEPENDENCY STATUS CHECK  (read-only — no installs)
#  Called by -e flag. To install missing tools, run: ./install.sh
# =============================================================================

check_deps() {
  section "Tool Status Check"
  info "Checking all required tools (read-only — no changes made)..."
  echo ""

  local installed_count=0
  local missing_count=0
  local missing_tools=()

  # ── Python venv ────────────────────────────────────────────────────────────
  if [ -d "$RECON_VENV" ]; then
    ok  "Python venv   : exists → $RECON_VENV"
  else
    warn "Python venv   : not found → $RECON_VENV"
    warn "  Run './install.sh' to create it."
  fi

  # ── Add venv + Go bin to PATH so pip/go-installed tools are visible ────────
  local venv_bin="$RECON_VENV/bin"
  [[ ":$PATH:" != *":$venv_bin:"* ]] && export PATH="$venv_bin:$PATH"
  local go_bin="$TOOLS_DIR/go/bin"
  [[ ":$PATH:" != *":$go_bin:"* ]] && export PATH="$go_bin:$PATH"

  # ── Go ─────────────────────────────────────────────────────────────────────
  echo ""
  if has go; then
    ok "go            : $(go version 2>/dev/null)"
  else
    warn "go            : not found"
    missing_tools+=("go"); missing_count=$((missing_count + 1))
  fi

  # ── python3 ────────────────────────────────────────────────────────────────
  if has python3; then
    ok "python3       : $(python3 --version 2>&1)"
  else
    warn "python3       : not found"
    missing_tools+=("python3"); missing_count=$((missing_count + 1))
  fi

  # ── pip3 ───────────────────────────────────────────────────────────────────
  local pip_bin=""
  if [ -x "$venv_bin/pip" ]; then
    pip_bin="$venv_bin/pip"
    ok "pip (venv)    : $("$pip_bin" --version 2>&1)"
  elif has pip3; then
    pip_bin="pip3"
    ok "pip3          : $(pip3 --version 2>&1)"
  else
    warn "pip3          : not found"
    missing_tools+=("pip3"); missing_count=$((missing_count + 1))
  fi

  # ── Each tool in DEPS ─────────────────────────────────────────────────────
  echo ""
  printf "  ${BOLD}%-20s %-12s %s${NC}\n" "TOOL" "METHOD" "STATUS"
  printf "  %s\n" "────────────────────────────────────────────────────────"

  for dep in "${DEPS[@]}"; do
    local tool="${dep%%:*}"
    local remainder="${dep#*:}"
    local method="${remainder%%:*}"
    local bin; bin=$(_binary_name "$tool")
    local found=0 tool_path=""
    case "$method" in
      go)
        if [ -x "$TOOLS_DIR/go/bin/$bin" ]; then
          found=1; tool_path="$TOOLS_DIR/go/bin/$bin"
        fi
        ;;
      *)
        if has "$bin"; then
          found=1; tool_path=$(command -v "$bin")
        fi
        ;;
    esac
    if [ "$found" -eq 1 ]; then
      printf "  ${GREEN}[OK ]${NC}  %-18s %-12s %s\n" "$tool" "$method" "$tool_path"
      installed_count=$((installed_count + 1))
    else
      printf "  ${RED}[---]${NC}  %-18s %-12s not found\n" "$tool" "$method"
      missing_tools+=("$tool")
      missing_count=$((missing_count + 1))
    fi
  done

  # ── Summary ───────────────────────────────────────────────────────────────
  echo ""
  echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
  echo -e "${BOLD}${CYAN}│  Tool Status Summary                                     │${NC}"
  echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
  echo ""
  ok "Installed : $installed_count / $((installed_count + missing_count))"
  if [ "$missing_count" -gt 0 ]; then
    warn "Missing   : $missing_count"
    warn "Tools     : ${missing_tools[*]}"
    echo ""
    info "To install all missing tools, run:"
    echo "    ./install.sh"
    echo ""
    return 1
  else
    ok "All tools are installed and available."
    echo ""
  fi
}

# Replace any live API key values with **** before writing to the log
_sanitize() {
  local s="$1"
  local k
  for k in "$API_SHODAN" "$API_GITHUB" "$API_VIRUSTOTAL" \
            "$API_SECURITYTRAILS" "$API_CENSYS_ID" "$API_CENSYS_SECRET" "$API_OTX"; do
    [ -n "$k" ] && s="${s//$k/****}"
  done
  printf '%s' "$s"
}

# Spinner animation — launched in background by run(); killed on completion
_spinner() {
  local label="$1"
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  tput civis 2>/dev/null || true          # hide cursor
  while true; do
    printf "\r  ${CYAN}${frames[$i]}${NC}  %-55s" "$label..."
    i=$(( (i + 1) % ${#frames[@]} ))
    sleep 0.1
  done
}

# Run a labelled command with a live spinner, timeout, and elapsed time; never aborts on non-zero
run() {
  local label="$1"; shift
  cmd_echo "$*"
  echo "[$(date '+%H:%M:%S')] $label: $(_sanitize "$*")" >> "$LOG_FILE"

  _spinner "$label" &
  _SPINNER_PID=$!

  local _start=$SECONDS
  timeout "$TOOL_TIMEOUT" "$@" >>"$LOG_FILE" 2>&1
  local exit_code=$?
  local _elapsed=$(( SECONDS - _start ))

  kill "$_SPINNER_PID" 2>/dev/null
  wait "$_SPINNER_PID" 2>/dev/null
  _SPINNER_PID=""
  tput cnorm 2>/dev/null || true
  printf "\r\033[K"

  # Format elapsed as Xs or MmSs
  local _dur
  if [ "$_elapsed" -ge 60 ]; then
    _dur="$(( _elapsed / 60 ))m$(( _elapsed % 60 ))s"
  else
    _dur="${_elapsed}s"
  fi

  if [ "$exit_code" -eq 0 ]; then
    ok "$label ${DIM}(${_dur})${NC}"
  elif [ "$exit_code" -eq 124 ]; then
    warn "$label — timed out after ${TOOL_TIMEOUT}s"
    [ -n "${OUTPUT_DIR:-}" ] && echo "[TIMEOUT] $label" >> "$OUTPUT_DIR/.failed_tools" 2>/dev/null || true
  else
    warn "$label — returned non-zero in ${_dur} (see log)"
    [ -n "${OUTPUT_DIR:-}" ] && echo "[FAILED]  $label" >> "$OUTPUT_DIR/.failed_tools" 2>/dev/null || true
  fi
}

# Resolve a wordlist from common locations
resolve_wordlist() {
  local candidates=(
    "$WORDLIST"
    /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
    /usr/share/seclists/Discovery/Web-Content/common.txt
    /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
    /opt/SecLists/Discovery/Web-Content/common.txt
    /usr/share/wordlists/dirb/common.txt
    /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
  )
  for f in "${candidates[@]}"; do
    [ -f "$f" ] && { echo "$f"; return; }
  done
  echo ""
}

linecount() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo "0"; }

setup() {
  # ── PID lock file — prevent concurrent runs against the same domain ────────
  local _safe_domain; _safe_domain=$(printf '%s' "$DOMAIN" | tr -dc 'a-zA-Z0-9.-' | tr '.' '_')
  LOCK_FILE="/tmp/rec0nzer0_${_safe_domain}.lock"
  if [ -f "$LOCK_FILE" ]; then
    local _old_pid; _old_pid=$(cat "$LOCK_FILE" 2>/dev/null)
    if kill -0 "$_old_pid" 2>/dev/null; then
      err "Rec0n-Zer0 is already running against $DOMAIN (PID $_old_pid)"
      err "Kill that process or delete $LOCK_FILE to force a new run."
      exit 1
    else
      warn "Stale lock file found — removing (PID $_old_pid no longer running)"
      rm -f "$LOCK_FILE"
    fi
  fi
  echo $$ > "$LOCK_FILE"

  # ── Disk space check (require 500 MB free on script partition) ─────────────
  local _min_mb=500
  local _avail_kb _avail_mb
  # -P (POSIX) prevents line-wrapping for long device names
  _avail_kb=$(df -Pk "$SCRIPT_DIR" 2>/dev/null | awk 'NR==2 {print $4}') || _avail_kb=0
  _avail_mb=$(( _avail_kb / 1024 ))
  if [ "$_avail_mb" -lt "$_min_mb" ]; then
    err "Insufficient disk space: ${_avail_mb}MB available on $SCRIPT_DIR, ${_min_mb}MB required"
    err "Free up space before scanning."
    exit 1
  fi
  info "Disk space  : ${_avail_mb}MB available on $SCRIPT_DIR"

  OUTPUT_DIR="${DOMAIN}_recon_$(date '+%Y%m%d_%H%M%S')"
  mkdir -p "$OUTPUT_DIR"/{subdomains,dns,ports,http,content,urls,vulns,screenshots,takeover}
  LOG_FILE="$OUTPUT_DIR/recon.log"
  touch "$LOG_FILE"
  SCAN_START=$SECONDS
  ok "Output      : ${BOLD}$OUTPUT_DIR${NC}"
}

# =============================================================================
#  API KEY MANAGEMENT
# =============================================================================

# Show first 4 chars of a key followed by **** (or "not set" if empty)
mask_key() {
  local k="$1"
  if [ -z "$k" ]; then
    printf "${DIM}not set${NC}"
  elif [ "${#k}" -le 8 ]; then
    printf "${GREEN}set (short)${NC}"
  else
    printf "${GREEN}%.4s****${NC}" "$k"
  fi
}

# Load API keys from the config file (silently skip if file doesn't exist)
load_api_keys() {
  [ -f "$RECON_API_CONFIG" ] || return 0
  while IFS='=' read -r key value; do
    # Skip comments and blank lines
    case "$key" in '#'*|'') continue ;; esac
    case "$key" in
      API_SHODAN)          API_SHODAN="$value"          ;;
      API_GITHUB)          API_GITHUB="$value"          ;;
      API_VIRUSTOTAL)      API_VIRUSTOTAL="$value"      ;;
      API_SECURITYTRAILS)  API_SECURITYTRAILS="$value"  ;;
      API_CENSYS_ID)       API_CENSYS_ID="$value"       ;;
      API_CENSYS_SECRET)   API_CENSYS_SECRET="$value"   ;;
      API_OTX)             API_OTX="$value"             ;;
    esac
  done < "$RECON_API_CONFIG"
}

# Save current API keys to config file (chmod 600)
# Validate an API key by format; prints a warning if suspicious but never blocks saving
# Usage: _validate_key "label" "value" "min_len" "pattern"
_validate_key() {
  local label="$1" val="$2" min_len="$3" pattern="$4"
  [ -z "$val" ] && return 0                              # empty = cleared, always ok
  if [ "${#val}" -lt "$min_len" ]; then
    warn "$label looks short (${#val} chars, expected >=$min_len) — double-check it"
  elif [ -n "$pattern" ] && ! printf '%s' "$val" | grep -qE "$pattern"; then
    warn "$label format looks unexpected — double-check it"
  else
    ok "$label format looks valid"
  fi
}

save_api_keys() {
  mkdir -p "$(dirname "$RECON_API_CONFIG")"
  cat > "$RECON_API_CONFIG" <<APIEOF
# Rec0n-Zer0.sh API key config — generated $(date)
# All keys are optional. Delete or leave blank to disable.
API_SHODAN=${API_SHODAN}
API_GITHUB=${API_GITHUB}
API_VIRUSTOTAL=${API_VIRUSTOTAL}
API_SECURITYTRAILS=${API_SECURITYTRAILS}
API_CENSYS_ID=${API_CENSYS_ID}
API_CENSYS_SECRET=${API_CENSYS_SECRET}
API_OTX=${API_OTX}
APIEOF
  chmod 600 "$RECON_API_CONFIG"
  ok "API keys saved → $RECON_API_CONFIG"
}

# Count how many API keys are currently set
count_set_keys() {
  local count=0
  for k in "$API_SHODAN" "$API_GITHUB" "$API_VIRUSTOTAL" \
            "$API_SECURITYTRAILS" "$API_CENSYS_ID" "$API_CENSYS_SECRET" "$API_OTX"; do
    [ -n "$k" ] && count=$((count + 1))
  done
  echo "$count"
}

# Build a temp subfinder provider config YAML from any set API keys.
# Prints the temp file path; prints nothing if no relevant keys are set.
build_subfinder_config() {
  if [ -z "$API_SHODAN" ] && [ -z "$API_GITHUB" ] && [ -z "$API_VIRUSTOTAL" ] \
     && [ -z "$API_SECURITYTRAILS" ] && [ -z "$API_CENSYS_ID" ]; then
    echo ""
    return
  fi
  local tmp; tmp=$(mktemp /tmp/subfinder_cfg_XXXXXX.yaml)
  {
    echo "# subfinder provider config — auto-generated by Rec0n-Zer0.sh"
    [ -n "$API_SHODAN" ]          && printf "shodan:\n  - %s\n"         "$API_SHODAN"
    [ -n "$API_GITHUB" ]          && printf "github:\n  - %s\n"         "$API_GITHUB"
    [ -n "$API_VIRUSTOTAL" ]      && printf "virustotal:\n  - %s\n"     "$API_VIRUSTOTAL"
    [ -n "$API_SECURITYTRAILS" ]  && printf "securitytrails:\n  - %s\n" "$API_SECURITYTRAILS"
    if [ -n "$API_CENSYS_ID" ] && [ -n "$API_CENSYS_SECRET" ]; then
      printf "censys:\n  - %s:%s\n" "$API_CENSYS_ID" "$API_CENSYS_SECRET"
    fi
  } > "$tmp"
  echo "$tmp"
}

# Interactive menu to add/clear/save API keys
configure_api_keys() {
  while true; do
    echo ""
    echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}│  API Key Configuration                                   │${NC}"
    echo -e "${BOLD}${CYAN}│  Config: ~/.config/recon/api_keys.conf (chmod 600)       │${NC}"
    echo -e "${BOLD}${CYAN}│  Tools work without keys — keys increase coverage        │${NC}"
    echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    printf "  ${YELLOW}1${NC}  shodan         API key           : "; echo -e "$(mask_key "$API_SHODAN")"
    printf "  ${YELLOW}2${NC}  github         Token             : "; echo -e "$(mask_key "$API_GITHUB")"
    printf "  ${YELLOW}3${NC}  virustotal     API key           : "; echo -e "$(mask_key "$API_VIRUSTOTAL")"
    printf "  ${YELLOW}4${NC}  securitytrails API key           : "; echo -e "$(mask_key "$API_SECURITYTRAILS")"
    printf "  ${YELLOW}5${NC}  censys         API ID            : "; echo -e "$(mask_key "$API_CENSYS_ID")"
    printf "  ${YELLOW}6${NC}  censys         API Secret        : "; echo -e "$(mask_key "$API_CENSYS_SECRET")"
    printf "  ${YELLOW}7${NC}  alienVault OTX API key           : "; echo -e "$(mask_key "$API_OTX")"
    echo ""
    echo -e "  ${DIM}Used by:  1,2,3,4,5,6→subfinder  1,3→findomain  7→gau${NC}"
    echo ""
    echo -e "  ${YELLOW}S${NC}  Save keys to config file"
    echo -e "  ${YELLOW}C${NC}  Clear a key"
    echo -e "  ${YELLOW}0${NC}  Back to main menu"
    echo ""
    read -rp "$(echo -e "${BOLD}Select [1-7 / S / C / 0]: ${NC}")" ak_choice

    case "$ak_choice" in
      0) return ;;
      [Ss]) save_api_keys ;;
      [Cc])
        read -rp "Key number to clear [1-7]: " clr
        case "$clr" in
          1) API_SHODAN="";          ok "Shodan key cleared" ;;
          2) API_GITHUB="";          ok "GitHub token cleared" ;;
          3) API_VIRUSTOTAL="";      ok "VirusTotal key cleared" ;;
          4) API_SECURITYTRAILS="";  ok "SecurityTrails key cleared" ;;
          5) API_CENSYS_ID="";       ok "Censys ID cleared" ;;
          6) API_CENSYS_SECRET="";   ok "Censys Secret cleared" ;;
          7) API_OTX="";             ok "OTX key cleared" ;;
          *) err "Invalid number" ;;
        esac
        ;;
      1)
        read -rsp "$(echo -e "${BOLD}Shodan API key (input hidden): ${NC}")" v; echo
        API_SHODAN="$v"
        _validate_key "Shodan"         "$v" 32 '^[a-zA-Z0-9]{32,}$'
        ;;
      2)
        read -rsp "$(echo -e "${BOLD}GitHub token (input hidden): ${NC}")" v; echo
        API_GITHUB="$v"
        _validate_key "GitHub token"   "$v" 40 '^(ghp_|github_pat_|[a-f0-9]{40})'
        ;;
      3)
        read -rsp "$(echo -e "${BOLD}VirusTotal API key (input hidden): ${NC}")" v; echo
        API_VIRUSTOTAL="$v"
        _validate_key "VirusTotal"     "$v" 64 '^[a-f0-9]{64}$'
        ;;
      4)
        read -rsp "$(echo -e "${BOLD}SecurityTrails API key (input hidden): ${NC}")" v; echo
        API_SECURITYTRAILS="$v"
        _validate_key "SecurityTrails" "$v" 20 '^[a-zA-Z0-9_-]{20,}$'
        ;;
      5)
        read -rsp "$(echo -e "${BOLD}Censys API ID (input hidden): ${NC}")" v; echo
        API_CENSYS_ID="$v"
        _validate_key "Censys ID"      "$v" 20 '^[a-zA-Z0-9_-]{20,}$'
        ;;
      6)
        read -rsp "$(echo -e "${BOLD}Censys API Secret (input hidden): ${NC}")" v; echo
        API_CENSYS_SECRET="$v"
        _validate_key "Censys Secret"  "$v" 20 '^[a-zA-Z0-9_-]{20,}$'
        ;;
      7)
        read -rsp "$(echo -e "${BOLD}AlienVault OTX API key (input hidden): ${NC}")" v; echo
        API_OTX="$v"
        _validate_key "OTX"            "$v" 64 '^[a-f0-9]{64}$'
        ;;
      *) err "Invalid selection" ;;
    esac
  done
}

# =============================================================================
#  PROFILES
# =============================================================================

apply_profile() {
  local profile="$1"
  CURRENT_PROFILE="$profile"

  case "$profile" in

    # ── Quick: fast, essential-only (~10–20 min) ──────────────────────────────
    quick)
      # Subdomain
      ENABLE_SUBFINDER=1;  ENABLE_AMASS=0;     ENABLE_ASSETFINDER=0
      ENABLE_FINDOMAIN=0
      # DNS
      ENABLE_DNSX=1;       ENABLE_DNSRECON=0;  ENABLE_NMAP_DNS=0;  ENABLE_DIG=1
      # Ports
      ENABLE_NAABU=0;      ENABLE_NMAP=1;      ENABLE_MASSCAN=0
      # HTTP
      ENABLE_HTTPX=1;      ENABLE_WAFW00F=0
      # Content
      ENABLE_FFUF=1;       ENABLE_GOBUSTER=0;  ENABLE_FEROXBUSTER=0; ENABLE_DIRSEARCH=0
      # URLs
      ENABLE_WAYBACKURLS=1; ENABLE_GAU=0;      ENABLE_KATANA=0
      ENABLE_GOSPIDER=0;   ENABLE_GF=0
      # Vulns
      ENABLE_NUCLEI=1;     ENABLE_NIKTO=0
      # Screenshots
      ENABLE_GOWITNESS=1;  ENABLE_AQUATONE=0
      # Secrets
      ENABLE_TRUFFLEHOG=0; ENABLE_GITLEAKS=0
      ok "Profile set → ${BOLD}QUICK${NC} (fast & lean)"
      ;;

    # ── Standard: balanced, recommended (default) ────────────────────────────
    standard)
      ENABLE_SUBFINDER=1;  ENABLE_AMASS=1;     ENABLE_ASSETFINDER=1
      ENABLE_FINDOMAIN=1
      ENABLE_DNSX=1;       ENABLE_DNSRECON=1;  ENABLE_NMAP_DNS=1;  ENABLE_DIG=1
      ENABLE_NAABU=1;      ENABLE_NMAP=1;      ENABLE_MASSCAN=0
      ENABLE_HTTPX=1;      ENABLE_WAFW00F=1
      ENABLE_FFUF=1;       ENABLE_GOBUSTER=1;  ENABLE_FEROXBUSTER=0; ENABLE_DIRSEARCH=0
      ENABLE_WAYBACKURLS=1; ENABLE_GAU=1;      ENABLE_KATANA=1
      ENABLE_GOSPIDER=0;   ENABLE_GF=1
      ENABLE_NUCLEI=1;     ENABLE_NIKTO=0
      ENABLE_GOWITNESS=1;  ENABLE_AQUATONE=0
      ENABLE_TRUFFLEHOG=0; ENABLE_GITLEAKS=1
      ok "Profile set → ${BOLD}STANDARD${NC} (balanced)"
      ;;

    # ── Comprehensive: everything on ─────────────────────────────────────────
    comprehensive)
      ENABLE_SUBFINDER=1;  ENABLE_AMASS=1;     ENABLE_ASSETFINDER=1
      ENABLE_FINDOMAIN=1
      ENABLE_DNSX=1;       ENABLE_DNSRECON=1;  ENABLE_NMAP_DNS=1;  ENABLE_DIG=1
      ENABLE_NAABU=1;      ENABLE_NMAP=1;      ENABLE_MASSCAN=0
      ENABLE_HTTPX=1;      ENABLE_WAFW00F=1
      ENABLE_FFUF=1;       ENABLE_GOBUSTER=1;  ENABLE_FEROXBUSTER=1; ENABLE_DIRSEARCH=1
      ENABLE_WAYBACKURLS=1; ENABLE_GAU=1;      ENABLE_KATANA=1
      ENABLE_GOSPIDER=1;   ENABLE_GF=1
      ENABLE_NUCLEI=1;     ENABLE_NIKTO=1
      ENABLE_GOWITNESS=1;  ENABLE_AQUATONE=1
      ENABLE_TRUFFLEHOG=1; ENABLE_GITLEAKS=1
      ok "Profile set → ${BOLD}COMPREHENSIVE${NC} (all tools)"
      ;;

    *) err "Unknown profile: $profile" ;;
  esac
}

# =============================================================================
#  CONFIGURE TOOLS MENU
# =============================================================================

configure_tools() {
  local groups=(
    "── Subdomain Enumeration ──:HEADER"
    "subfinder:subfinder"
    "amass:amass"
    "assetfinder:assetfinder"
    "findomain:findomain"
    "── DNS ──:HEADER"
    "dnsx:dnsx"
    "dnsrecon:dnsrecon"
    "nmap DNS scripts:nmap_dns"
    "dig:dig"
    "── Port Scanning ──:HEADER"
    "naabu:naabu"
    "nmap:nmap"
    "masscan (needs root):masscan"
    "── HTTP Probing ──:HEADER"
    "httpx:httpx"
    "wafw00f:wafw00f"
    "── Content Discovery ──:HEADER"
    "ffuf:ffuf"
    "gobuster:gobuster"
    "feroxbuster:feroxbuster"
    "dirsearch:dirsearch"
    "── URL Discovery ──:HEADER"
    "waybackurls:waybackurls"
    "gau:gau"
    "katana:katana"
    "gospider:gospider"
    "gf (param extractor):gf"
    "── Vulnerability Scanning ──:HEADER"
    "nuclei:nuclei"
    "nikto (slow):nikto"
    "── Screenshots ──:HEADER"
    "gowitness:gowitness"
    "aquatone:aquatone"
    "── Secret Scanning ──:HEADER"
    "trufflehog:trufflehog"
    "gitleaks:gitleaks"
  )

  while true; do
    echo ""
    echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}│  Configure Tools — toggle ON/OFF                         │${NC}"
    echo -e "${BOLD}${CYAN}│  Profile: ${YELLOW}${CURRENT_PROFILE}${CYAN}$(printf '%*s' $((41 - ${#CURRENT_PROFILE})) '')│${NC}"
    echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""

    local idx=0
    local tool_indices=()  # maps display number → tool key

    for entry in "${groups[@]}"; do
      local label="${entry%%:*}"
      local key="${entry##*:}"

      if [ "$key" = "HEADER" ]; then
        echo -e "  ${BOLD}${YELLOW}$label${NC}"
        continue
      fi

      idx=$((idx + 1))
      tool_indices+=("$key")

      local install_info; install_info=$(install_badge "$key")
      printf "  %3d. $(status_badge "$key")  %-28s %b\n" \
        "$idx" "$label" "$install_info"
    done

    echo ""
    echo -e "  ${BOLD}P${NC}  Apply profile  (Q)uick / (S)tandard / (C)omprehensive"
    echo -e "  ${BOLD}R${NC}  Reset to current profile defaults"
    echo -e "  ${BOLD}0${NC}  Back to main menu"
    echo ""
    read -rp "$(echo -e "${BOLD}Toggle tool # (or P/R/0): ${NC}")" choice

    case "$choice" in
      0) return ;;
      [Pp])
        read -rp "Profile [q]uick / [s]tandard / [c]omprehensive: " pr
        case "$pr" in
          q|Q) apply_profile quick ;;
          s|S) apply_profile standard ;;
          c|C) apply_profile comprehensive ;;
          *) err "Unknown profile" ;;
        esac
        ;;
      [Rr]) apply_profile "$CURRENT_PROFILE" ;;
      ''|*[!0-9]*)
        err "Enter a number, or P / R / 0" ;;
      *)
        if [ "$choice" -ge 1 ] && [ "$choice" -le "${#tool_indices[@]}" ]; then
          local tkey="${tool_indices[$((choice - 1))]}"
          toggle_tool "$tkey"
          local varname="ENABLE_$(echo "$tkey" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
          local new_val="${!varname:-1}"
          [ "$new_val" -eq 1 ] \
            && ok "${tkey} → ${GREEN}ENABLED${NC}" \
            || ok "${tkey} → ${RED}DISABLED${NC}"
        else
          err "Number out of range"
        fi
        ;;
    esac
  done
}

# Query crt.sh certificate transparency logs for passive subdomain discovery
_query_crtsh() {
  local domain="$1" outfile="$2"
  curl -s --connect-timeout 15 --max-time 30 \
    "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null \
  | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    seen = set()
    for entry in data:
        for name in entry.get('name_value','').split('\n'):
            name = name.strip().lstrip('*.')
            if name and '${domain}' in name and name not in seen:
                seen.add(name)
                print(name)
except Exception:
    pass
" 2>/dev/null | sort -u > "$outfile" || true
}

# =============================================================================
#  RECON MODULES
# =============================================================================

subdomain_enum() {
  section "SUBDOMAIN ENUMERATION"
  local out="$OUTPUT_DIR/subdomains"
  local pids=()
  local tool_names=()
  local _tmpfiles=()

  # ── Launch all enabled tools as background jobs ────────────────────────────
  if use subfinder; then
    local sf_config; sf_config=$(build_subfinder_config)
    if [ -n "$sf_config" ]; then
      echo "[$(date '+%H:%M:%S')] subfinder (API keys active): subfinder -d $DOMAIN ..." >> "$LOG_FILE"
      subfinder -d "$DOMAIN" -all -recursive -silent -pc "$sf_config" \
        -o "$out/subfinder.txt" >>"$LOG_FILE" 2>&1 &
      pids+=($!); tool_names+=("subfinder"); _tmpfiles+=("$sf_config")
    else
      echo "[$(date '+%H:%M:%S')] subfinder: subfinder -d $DOMAIN ..." >> "$LOG_FILE"
      subfinder -d "$DOMAIN" -all -recursive -silent \
        -o "$out/subfinder.txt" >>"$LOG_FILE" 2>&1 &
      pids+=($!); tool_names+=("subfinder")
    fi
  fi

  if use amass; then
    echo "[$(date '+%H:%M:%S')] amass: amass enum -passive -d $DOMAIN ..." >> "$LOG_FILE"
    amass enum -passive -d "$DOMAIN" -o "$out/amass.txt" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("amass")
  fi

  if use assetfinder; then
    echo "[$(date '+%H:%M:%S')] assetfinder: assetfinder --subs-only $DOMAIN ..." >> "$LOG_FILE"
    assetfinder --subs-only "$DOMAIN" > "$out/assetfinder.txt" 2>>"$LOG_FILE" &
    pids+=($!); tool_names+=("assetfinder")
  fi

  if use findomain; then
    local fd_env=()
    [ -n "$API_VIRUSTOTAL" ] && fd_env+=("VIRUSTOTAL_ACCESS_KEY=$API_VIRUSTOTAL")
    [ -n "$API_SHODAN" ]     && fd_env+=("SHODAN_API_KEY=$API_SHODAN")
    echo "[$(date '+%H:%M:%S')] findomain: findomain -t $DOMAIN ..." >> "$LOG_FILE"
    env "${fd_env[@]}" findomain -t "$DOMAIN" -q \
      > "$out/findomain.txt" 2>>"$LOG_FILE" || true &
    pids+=($!); tool_names+=("findomain")
  fi

  # ── crt.sh — certificate transparency passive query ───────────────────────
  if has curl && has python3; then
    echo "[$(date '+%H:%M:%S')] crt.sh: querying certificate transparency logs..." >> "$LOG_FILE"
    _query_crtsh "$DOMAIN" "$out/crtsh.txt" &
    pids+=($!); tool_names+=("crt.sh")
  fi

  # ── Single spinner while all jobs run in parallel ──────────────────────────
  if [ "${#pids[@]}" -gt 0 ]; then
    local joined; joined=$(IFS=', '; echo "${tool_names[*]}")
    _spinner "Running ${#pids[@]} tools in parallel  [ ${joined} ]" &
    _SPINNER_PID=$!

    local failed=0
    for pid in "${pids[@]}"; do
      wait "$pid" || failed=$((failed + 1))
    done

    kill "$_SPINNER_PID" 2>/dev/null
    wait "$_SPINNER_PID" 2>/dev/null
    _SPINNER_PID=""
    tput cnorm 2>/dev/null || true
    printf "\r\033[K"

    [ "$failed" -eq 0 ] \
      && ok "All ${#tool_names[@]} subdomain tools completed" \
      || warn "$failed tool(s) returned non-zero (see log)"
  else
    warn "No subdomain tools enabled or installed — skipping"
  fi

  # ── Cleanup temp files (e.g. subfinder provider config) ───────────────────
  for f in "${_tmpfiles[@]}"; do rm -f "$f" 2>/dev/null || true; done

  # ── Combine and deduplicate ────────────────────────────────────────────────
  info "Combining and deduplicating..."
  cat "$out"/*.txt 2>/dev/null | sort -u | grep -v '^$' > "$out/all_subdomains.txt" || true
  ok "Unique subdomains : $(linecount "$out/all_subdomains.txt")"
  ok "Saved → $out/all_subdomains.txt"
}

dns_enum() {
  section "DNS ENUMERATION"
  local out="$OUTPUT_DIR/dns"
  local subs="$OUTPUT_DIR/subdomains/all_subdomains.txt"
  local pids=()
  local tool_names=()

  # ── Wildcard DNS detection ─────────────────────────────────────────────────
  local _test_sub="wildcard-test-$$-$(date +%s)"
  info "Checking for wildcard DNS on $DOMAIN..."
  if dig +short "${_test_sub}.${DOMAIN}" A 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    warn "Wildcard DNS detected! All subdomains appear to resolve — results may be noisy"
    warn "Consider filtering resolved IPs against the wildcard address"
    echo "WILDCARD_DETECTED=1" > "$out/wildcard_dns.txt"
    dig +short "${_test_sub}.${DOMAIN}" A 2>/dev/null >> "$out/wildcard_dns.txt" || true
  else
    ok "No wildcard DNS detected"
  fi

  # ── Launch DNS tools in parallel ──────────────────────────────────────────
  if use dnsx; then
    if [ -f "$subs" ] && [ "$(linecount "$subs")" -gt 0 ]; then
      echo "[$(date '+%H:%M:%S')] dnsx-resolve: dnsx -l $subs ..." >> "$LOG_FILE"
      dnsx -l "$subs" -a -aaaa -cname -mx -ns -txt -resp -silent \
        -o "$out/resolved.txt" >>"$LOG_FILE" 2>&1 &
      pids+=($!); tool_names+=("dnsx-resolve")
    fi
    echo "[$(date '+%H:%M:%S')] dnsx-axfr: echo $DOMAIN | dnsx -axfr ..." >> "$LOG_FILE"
    { printf '%s\n' "$DOMAIN" | dnsx -axfr -silent -o "$out/zone_transfer.txt" 2>/dev/null || true; } \
      >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("dnsx-axfr")
  fi

  if use dnsrecon; then
    echo "[$(date '+%H:%M:%S')] dnsrecon-std: dnsrecon -d $DOMAIN -t std ..." >> "$LOG_FILE"
    dnsrecon -d "$DOMAIN" -t std -j "$out/dnsrecon_std.json" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("dnsrecon-std")

    echo "[$(date '+%H:%M:%S')] dnsrecon-axfr: dnsrecon -d $DOMAIN -t axfr ..." >> "$LOG_FILE"
    dnsrecon -d "$DOMAIN" -t axfr -j "$out/dnsrecon_axfr.json" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("dnsrecon-axfr")

    echo "[$(date '+%H:%M:%S')] dnsrecon-srv: dnsrecon -d $DOMAIN -t srv ..." >> "$LOG_FILE"
    dnsrecon -d "$DOMAIN" -t srv -j "$out/dnsrecon_srv.json" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("dnsrecon-srv")
  fi

  if use nmap_dns; then
    echo "[$(date '+%H:%M:%S')] nmap-dns: nmap -p 53 --script dns-* $DOMAIN ..." >> "$LOG_FILE"
    nmap -p 53 --script dns-zone-transfer,dns-brute,dns-srv-enum \
      --script-args "dns-brute.domain=$DOMAIN" \
      -oN "$out/nmap_dns.txt" "$DOMAIN" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("nmap-dns")
  fi

  # ── Single spinner while all DNS tools run ────────────────────────────────
  if [ "${#pids[@]}" -gt 0 ]; then
    local joined; joined=$(IFS=', '; echo "${tool_names[*]}")
    _spinner "Running ${#pids[@]} DNS tools in parallel  [ ${joined} ]" &
    _SPINNER_PID=$!

    local failed=0
    for pid in "${pids[@]}"; do
      wait "$pid" || failed=$((failed + 1))
    done

    kill "$_SPINNER_PID" 2>/dev/null
    wait "$_SPINNER_PID" 2>/dev/null
    _SPINNER_PID=""
    tput cnorm 2>/dev/null || true
    printf "\r\033[K"

    [ "$failed" -eq 0 ] \
      && ok "All ${#tool_names[@]} DNS tools completed" \
      || warn "$failed DNS tool(s) returned non-zero (see log)"
  else
    warn "No DNS tools enabled or installed — skipping parallel phase"
  fi

  # ── dig — quick A/MX/NS/TXT/SOA records (runs inline, milliseconds) ───────
  if use dig; then
    info "dig — pulling A/MX/NS/TXT/SOA records"
    {
      echo "=== A ==="   && dig +short A   "$DOMAIN"
      echo "=== MX ==="  && dig +short MX  "$DOMAIN"
      echo "=== NS ==="  && dig +short NS  "$DOMAIN"
      echo "=== TXT ===" && dig +short TXT "$DOMAIN"
      echo "=== SOA ===" && dig +short SOA "$DOMAIN"
    } > "$out/dig_records.txt" 2>>"$LOG_FILE" || true
    ok "Saved → $out/dig_records.txt"
  fi

  ok "Resolved : $(linecount "$out/resolved.txt")"
}

port_scan() {
  section "PORT SCANNING"
  local target="${1:-$DOMAIN}"
  local out="$OUTPUT_DIR/ports"
  info "Target : $target"

  use naabu && run "naabu — full port discovery" \
    naabu -host "$target" -p - -rate 2000 -silent -o "$out/naabu_open.txt"

  if use nmap; then
    run "nmap — top-1000, version & scripts" \
      nmap -sV -sC -T4 --open -oA "$out/nmap_quick" "$target"
    if [ -f "$out/naabu_open.txt" ] && [ "$(linecount "$out/naabu_open.txt")" -gt 0 ]; then
      local ports; ports=$(tr '\n' ',' < "$out/naabu_open.txt" | sed 's/,$//')
      run "nmap — deep scan on naabu ports" \
        nmap -sV -sC -p "$ports" --open -oA "$out/nmap_targeted" "$target"
    else
      run "nmap — full 65535-port scan" \
        nmap -p- -T4 --open -oA "$out/nmap_full" "$target"
    fi
  fi


  if use masscan; then
    if [ "$(id -u)" -eq 0 ]; then
      run "masscan — raw speed full range" \
        masscan "$target" -p 0-65535 --rate 10000 -oJ "$out/masscan.json"
    else
      warn "masscan requires root — skipping"
    fi
  fi

  ok "Port results → $out/"
}

# Feed naabu-discovered ports into httpx to catch web services on non-standard ports
_probe_naabu_ports() {
  local naabu_out="$OUTPUT_DIR/ports/naabu_open.txt"
  local http_out="$OUTPUT_DIR/http"

  [ -f "$naabu_out" ] || return 0
  [ "$(linecount "$naabu_out")" -gt 0 ] || return 0
  use httpx || return 0

  info "Probing $(linecount "$naabu_out") naabu-discovered endpoints with httpx..."
  run "httpx — probe naabu-discovered ports" \
    httpx -l "$naabu_out" \
      -title -status-code -tech-detect \
      -follow-redirects -random-agent -threads "$THREADS" -silent \
      -o "$http_out/live_naabu_ports.txt"

  # Merge with the standard probed hosts for a unified target list
  cat "$http_out/live_hosts.txt" "$http_out/live_naabu_ports.txt" 2>/dev/null \
    | sort -u > "$http_out/live_hosts_all.txt" || true
  ok "Merged live hosts : $(linecount "$http_out/live_hosts_all.txt") → $http_out/live_hosts_all.txt"
}

http_probe() {
  section "HTTP PROBING & TECH DETECTION"
  local input="${1:-$OUTPUT_DIR/subdomains/all_subdomains.txt}"
  local out="$OUTPUT_DIR/http"

  if [ ! -f "$input" ]; then
    warn "Input not found: $input — run Subdomain Enumeration first."
    return
  fi

  if use httpx; then
    run "httpx — probe standard ports (80/443)" \
      httpx -l "$input" \
        -title -tech-detect -status-code -content-length \
        -follow-redirects -random-agent -threads "$THREADS" -silent \
        -o "$out/live_hosts.txt"

    run "httpx — probe extra ports (8080/8443/8888/9090/3000)" \
      httpx -l "$input" \
        -ports 8080,8443,8888,9090,3000,4443,5000 \
        -title -status-code -follow-redirects -silent -threads "$THREADS" \
        -o "$out/live_extra_ports.txt"

    grep -oE 'https?://[^ ]+' "$out/live_hosts.txt" 2>/dev/null \
      | sort -u > "$out/live_urls.txt" || true
  fi

  use wafw00f && run "wafw00f — WAF fingerprinting" \
    bash -c "wafw00f 'https://$DOMAIN' > '$out/waf.txt' 2>/dev/null || true"

  ok "Live hosts : $(linecount "$out/live_hosts.txt")"
  ok "Results → $out/"
}

# =============================================================================
#  WORDLIST SELECTOR
# =============================================================================

select_wordlist() {
  echo ""
  echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
  echo -e "${BOLD}${CYAN}│  Select Wordlist for Content Discovery                   │${NC}"
  echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
  echo ""

  # Known wordlist paths to scan for
  local candidates=(
    "SecLists raft-large-words    (~63k) :/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
    "SecLists raft-medium-words   (~63k) :/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
    "SecLists raft-small-words    (~18k) :/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
    "SecLists common               (~4k) :/usr/share/seclists/Discovery/Web-Content/common.txt"
    "SecLists big                 (~20k) :/usr/share/seclists/Discovery/Web-Content/big.txt"
    "SecLists dir-list-2.3-medium (~220k):/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    "SecLists dir-list-2.3-small   (~87k):/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
    "SecLists api-endpoints         (~1k) :/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
    "SecLists quickhits             (~2k) :/usr/share/seclists/Discovery/Web-Content/quickhits.txt"
    "dirb common                   (~4k) :/usr/share/wordlists/dirb/common.txt"
    "dirb big                     (~20k) :/usr/share/wordlists/dirb/big.txt"
    "dirbuster medium             (~220k):/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "dirbuster small               (~87k):/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
  )

  local found_paths=()
  local found_labels=()

  echo -e "  ${BOLD}Available on this system:${NC}"
  echo ""

  local idx=0
  for entry in "${candidates[@]}"; do
    local label="${entry%%:*}"
    local path="${entry##*:}"
    if [ -f "$path" ]; then
      idx=$((idx + 1))
      found_paths+=("$path")
      found_labels+=("$label")
      local lines; lines=$(wc -l < "$path" | tr -d ' ')
      printf "  ${YELLOW}%2d${NC}  %-38s ${DIM}%s words${NC}\n" "$idx" "$label" "$lines"
    fi
  done

  if [ "$idx" -eq 0 ]; then
    warn "No known wordlists found on this system."
    warn "Install with:  sudo apt install seclists"
  fi

  echo ""
  echo -e "   ${YELLOW}C${NC}  Enter a custom path"
  if [ -n "$WORDLIST" ]; then
    echo -e "   ${YELLOW}K${NC}  Keep current: ${GREEN}$(basename "$WORDLIST")${NC}"
  fi
  echo -e "   ${YELLOW}0${NC}  Cancel"
  echo ""

  read -rp "$(echo -e "${BOLD}Select wordlist [number / C / K / 0]: ${NC}")" wchoice

  case "$wchoice" in
    0)  return ;;
    [Kk])
        if [ -n "$WORDLIST" ]; then
          ok "Keeping current wordlist: $WORDLIST"
        else
          warn "No wordlist currently set."
        fi
        ;;
    [Cc])
        read -rp "Enter full path to wordlist file: " custom_wl
        if [ -f "$custom_wl" ]; then
          WORDLIST="$custom_wl"
          local wc; wc=$(wc -l < "$WORDLIST" | tr -d ' ')
          ok "Wordlist set → $WORDLIST  (${wc} words)"
        else
          err "File not found: $custom_wl"
        fi
        ;;
    ''|*[!0-9]*)
        err "Invalid selection." ;;
    *)
        if [ "$wchoice" -ge 1 ] && [ "$wchoice" -le "${#found_paths[@]}" ]; then
          WORDLIST="${found_paths[$((wchoice - 1))]}"
          local wc; wc=$(wc -l < "$WORDLIST" | tr -d ' ')
          ok "Wordlist set → $WORDLIST  (${wc} words)"
        else
          err "Number out of range."
        fi
        ;;
  esac
}

# =============================================================================
#  CONTENT DISCOVERY
# =============================================================================

content_discovery() {
  section "CONTENT DISCOVERY"
  local target_url="${1:-https://$DOMAIN}"
  local out="$OUTPUT_DIR/content"
  local wl; wl=$(resolve_wordlist)

  # If auto-resolve found nothing, prompt the user to pick one
  if [ -z "$wl" ]; then
    warn "No wordlist found automatically."
    select_wordlist
    wl=$(resolve_wordlist)
    if [ -z "$wl" ]; then
      err "No wordlist selected. Content discovery skipped."
      return
    fi
  fi

  info "Wordlist : $wl"
  info "Target   : $target_url"

  local pids=()
  local tool_names=()

  # ── Launch all content discovery tools in parallel ─────────────────────────
  if use ffuf; then
    echo "[$(date '+%H:%M:%S')] ffuf-dirs: ffuf -w $wl -u $target_url/FUZZ ..." >> "$LOG_FILE"
    ffuf -w "$wl" -u "$target_url/FUZZ" \
      -mc 200,201,204,301,302,307,401,403,405 -c -t "$THREADS" -ac \
      -o "$out/ffuf_dirs.json" -of json >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("ffuf-dirs")

    echo "[$(date '+%H:%M:%S')] ffuf-files: ffuf -w $wl -u $target_url/FUZZ (ext) ..." >> "$LOG_FILE"
    ffuf -w "$wl" -u "$target_url/FUZZ" \
      -e .php,.html,.js,.txt,.bak,.zip,.env,.config,.yaml,.xml \
      -mc 200,201,204,301,302,401 -c -t "$THREADS" -ac \
      -o "$out/ffuf_files.json" -of json >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("ffuf-files")
  fi

  if use gobuster; then
    echo "[$(date '+%H:%M:%S')] gobuster: gobuster dir -u $target_url ..." >> "$LOG_FILE"
    gobuster dir -u "$target_url" -w "$wl" -t "$THREADS" -q \
      -o "$out/gobuster.txt" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("gobuster")
  fi

  if use feroxbuster; then
    echo "[$(date '+%H:%M:%S')] feroxbuster: feroxbuster -u $target_url ..." >> "$LOG_FILE"
    feroxbuster -u "$target_url" -w "$wl" -t "$THREADS" --depth 3 --quiet \
      -o "$out/feroxbuster.txt" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("feroxbuster")
  fi

  if use dirsearch; then
    echo "[$(date '+%H:%M:%S')] dirsearch: dirsearch -u $target_url ..." >> "$LOG_FILE"
    dirsearch -u "$target_url" -w "$wl" -t "$THREADS" -q \
      -o "$out/dirsearch.txt" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("dirsearch")
  fi

  # ── Single spinner while all content tools run ────────────────────────────
  if [ "${#pids[@]}" -gt 0 ]; then
    local joined; joined=$(IFS=', '; echo "${tool_names[*]}")
    _spinner "Running ${#pids[@]} content tools in parallel  [ ${joined} ]" &
    _SPINNER_PID=$!

    local failed=0
    for pid in "${pids[@]}"; do
      wait "$pid" || failed=$((failed + 1))
    done

    kill "$_SPINNER_PID" 2>/dev/null
    wait "$_SPINNER_PID" 2>/dev/null
    _SPINNER_PID=""
    tput cnorm 2>/dev/null || true
    printf "\r\033[K"

    [ "$failed" -eq 0 ] \
      && ok "All ${#tool_names[@]} content tools completed" \
      || warn "$failed content tool(s) returned non-zero (see log)"
  else
    warn "No content discovery tools enabled or installed — skipping"
  fi

  ok "Content results → $out/"
}

url_discovery() {
  section "URL DISCOVERY"
  local out="$OUTPUT_DIR/urls"
  local pids=()
  local tool_names=()

  # ── Launch all URL discovery tools in parallel ─────────────────────────────
  if use waybackurls; then
    echo "[$(date '+%H:%M:%S')] waybackurls: waybackurls $DOMAIN ..." >> "$LOG_FILE"
    bash -c "waybackurls '$DOMAIN' 2>>'$LOG_FILE' | sort -u > '$out/wayback.txt' || true" &
    pids+=($!); tool_names+=("waybackurls")
  fi

  if use gau; then
    if [ -n "$API_OTX" ]; then
      local gau_cfg; gau_cfg=$(mktemp /tmp/.gau_cfg_XXXXXX.toml)
      printf '[otx]\napikey = "%s"\n' "$API_OTX" > "$gau_cfg"
      chmod 600 "$gau_cfg"
      echo "[$(date '+%H:%M:%S')] gau+OTX: gau --threads 10 --subs $DOMAIN ..." >> "$LOG_FILE"
      bash -c "gau --threads 10 --subs --config '$gau_cfg' '$DOMAIN' 2>>'$LOG_FILE' \
        | sort -u > '$out/gau.txt'; rm -f '$gau_cfg' || true" &
    else
      echo "[$(date '+%H:%M:%S')] gau: gau --threads 10 --subs $DOMAIN ..." >> "$LOG_FILE"
      bash -c "gau --threads 10 --subs '$DOMAIN' 2>>'$LOG_FILE' | sort -u > '$out/gau.txt' || true" &
    fi
    pids+=($!); tool_names+=("gau")
  fi

  if use katana; then
    echo "[$(date '+%H:%M:%S')] katana: katana -u https://$DOMAIN -depth 5 ..." >> "$LOG_FILE"
    katana -u "https://$DOMAIN" -depth 5 -silent \
      -o "$out/katana.txt" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("katana")
  fi

  if use gospider; then
    echo "[$(date '+%H:%M:%S')] gospider: gospider -s https://$DOMAIN ..." >> "$LOG_FILE"
    gospider -s "https://$DOMAIN" -c 10 -d 5 -q \
      -o "$out/gospider/" >>"$LOG_FILE" 2>&1 &
    pids+=($!); tool_names+=("gospider")
  fi

  # ── Single spinner while all URL tools run ────────────────────────────────
  if [ "${#pids[@]}" -gt 0 ]; then
    local joined; joined=$(IFS=', '; echo "${tool_names[*]}")
    _spinner "Running ${#pids[@]} URL tools in parallel  [ ${joined} ]" &
    _SPINNER_PID=$!

    local failed=0
    for pid in "${pids[@]}"; do
      wait "$pid" || failed=$((failed + 1))
    done

    kill "$_SPINNER_PID" 2>/dev/null
    wait "$_SPINNER_PID" 2>/dev/null
    _SPINNER_PID=""
    tput cnorm 2>/dev/null || true
    printf "\r\033[K"

    [ "$failed" -eq 0 ] \
      && ok "All ${#tool_names[@]} URL tools completed" \
      || warn "$failed URL tool(s) returned non-zero (see log)"
  else
    warn "No URL discovery tools enabled or installed — skipping"
  fi

  info "Deduplicating all URL sources..."
  cat "$out"/*.txt 2>/dev/null | grep -v '^$' | sort -u > "$out/all_urls.txt" || true
  ok "Total unique URLs : $(linecount "$out/all_urls.txt")"

  if use gf && [ -f "$out/all_urls.txt" ]; then
    info "gf — extracting parameter patterns..."
    for pat in sqli xss ssrf redirect rce lfi idor; do
      gf "$pat" < "$out/all_urls.txt" > "$out/params_${pat}.txt" 2>/dev/null \
        && ok "  $pat : $(linecount "$out/params_${pat}.txt") params" || true
    done
  fi

  grep -E '\.js(\?|$)' "$out/all_urls.txt" 2>/dev/null \
    | sort -u > "$out/js_files.txt" || true
  ok "JS files : $(linecount "$out/js_files.txt")"
  ok "Results → $out/"
}

vuln_scan() {
  section "VULNERABILITY SCANNING"
  local input="${1:-$OUTPUT_DIR/http/live_hosts.txt}"
  local out="$OUTPUT_DIR/vulns"

  if [ ! -f "$input" ]; then
    warn "Input not found: $input — run HTTP Probing first."
    return
  fi

  if use nuclei; then
    run "nuclei — update templates" \
      nuclei -update-templates -silent

    run "nuclei — full scan (critical → info)" \
      nuclei -l "$input" \
        -severity critical,high,medium,low,info \
        -o "$out/nuclei_full.txt" -silent

    # ── Post-process into severity-specific files (no extra network calls) ───
    info "Categorizing nuclei findings by severity..."
    grep ' \[critical\] ' "$out/nuclei_full.txt" 2>/dev/null | sort -u \
      > "$out/nuclei_critical.txt" || true
    grep ' \[high\] '     "$out/nuclei_full.txt" 2>/dev/null | sort -u \
      > "$out/nuclei_high.txt"     || true
    cat "$out/nuclei_critical.txt" "$out/nuclei_high.txt" 2>/dev/null | sort -u \
      > "$out/nuclei_crit_high.txt" || true
    grep -iE 'CVE-[0-9]{4}-[0-9]+' "$out/nuclei_full.txt" 2>/dev/null | sort -u \
      > "$out/nuclei_cves.txt"     || true
  fi

  use nikto && run "nikto — web server scan" \
    nikto -h "https://$DOMAIN" -o "$out/nikto.txt" -Format txt

  ok "Critical      : $(linecount "$out/nuclei_critical.txt")"
  ok "High          : $(linecount "$out/nuclei_high.txt")"
  ok "Critical/High : $(linecount "$out/nuclei_crit_high.txt")"
  ok "CVEs          : $(linecount "$out/nuclei_cves.txt")"
  ok "Full findings : $(linecount "$out/nuclei_full.txt")"
  ok "Results → $out/"
}

take_screenshots() {
  section "SCREENSHOTS"
  local input="${1:-$OUTPUT_DIR/http/live_hosts.txt}"
  local out="$OUTPUT_DIR/screenshots"

  if [ ! -f "$input" ]; then
    warn "Input not found: $input — run HTTP Probing first."
    return
  fi

  use gowitness && run "gowitness — screenshot live hosts" \
    gowitness file -f "$input" -P "$out/" --no-http

  use aquatone && run "aquatone — screenshot & cluster" \
    bash -c "cat '$input' | aquatone -out '$out/aquatone/' 2>/dev/null || true"

  ok "Screenshots → $out/"
}

whois_enum() {
  section "WHOIS ENUMERATION"
  local out="$OUTPUT_DIR/dns"

  if ! has whois; then
    warn "whois not installed — skipping (install via: sudo apt install whois)"
    return
  fi

  info "whois — querying registration data for $DOMAIN"
  whois "$DOMAIN" > "$out/whois_domain.txt" 2>>"$LOG_FILE" || true
  ok "Raw WHOIS → $out/whois_domain.txt"

  # Surface key fields inline for quick reading
  local _fields
  _fields=$(grep -iE \
    'registrant|registrar|creation date|expir|name server|status|admin email|tech email' \
    "$out/whois_domain.txt" 2>/dev/null | sort -u | head -20) || true
  if [ -n "$_fields" ]; then
    echo ""
    echo "$_fields" | while IFS= read -r line; do
      echo -e "  ${DIM}$line${NC}"
    done
    echo ""
  fi
}

subdomain_takeover() {
  section "SUBDOMAIN TAKEOVER CHECK"
  local input="${1:-$OUTPUT_DIR/subdomains/all_subdomains.txt}"
  local out="$OUTPUT_DIR/takeover"

  if [ ! -f "$input" ] || [ "$(linecount "$input")" -eq 0 ]; then
    warn "No subdomain list found — run Subdomain Enumeration first."
    return
  fi

  if ! use nuclei; then
    warn "nuclei not installed — skipping takeover check"
    return
  fi

  run "nuclei — subdomain takeover detection" \
    nuclei -l "$input" \
      -tags takeover \
      -severity medium,high,critical \
      -silent -o "$out/takeover_results.txt"

  local _hits; _hits=$(linecount "$out/takeover_results.txt")
  if [ "$_hits" -gt 0 ]; then
    warn "Potential takeovers found: $_hits — review $out/takeover_results.txt"
  else
    ok "No subdomain takeovers detected."
  fi
}

secret_scan() {
  section "JS SECRET SCANNING"
  local js_file="$OUTPUT_DIR/urls/js_files.txt"
  local out="$OUTPUT_DIR/vulns"

  if [ ! -f "$js_file" ] || [ "$(linecount "$js_file")" -eq 0 ]; then
    warn "No JS file list found. Run URL Discovery first."
    return
  fi

  info "Scanning $(linecount "$js_file") JS files..."

  use trufflehog && run "trufflehog — secrets in JS files" \
    bash -c "cat '$js_file' | while read url; do \
      trufflehog --json filesystem <(curl -sk \"\$url\") 2>/dev/null; \
    done > '$out/trufflehog_js.json' 2>/dev/null || true"

  use gitleaks && run "gitleaks — secrets in working directory" \
    bash -c "gitleaks detect --source . -v --report-path '$out/gitleaks.json' 2>/dev/null || true"

  use nuclei && run "nuclei — exposed tokens & API keys" \
    bash -c "cat '$js_file' | nuclei -tags token,keys,exposure \
      -o '$out/nuclei_secrets.txt' -silent 2>/dev/null || true"

  ok "Secret results → $out/"
}

# =============================================================================
#  RUN MODES
# =============================================================================

# ── Full Recon (all enabled modules in recommended order) ────────────────────
# Run a recon module in the background — terminal output suppressed, LOG_FILE writes intact
_module_bg() {
  ( "$@" ) >/dev/null 2>&1 &
  echo $!
}

full_recon() {
  echo ""
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}${CYAN}  FULL RECON — Profile: ${YELLOW}${CURRENT_PROFILE}${NC}"
  echo -e "${BOLD}${CYAN}  Target  : ${GREEN}$DOMAIN${NC}"
  echo -e "${BOLD}${CYAN}  Output  : ${GREEN}$OUTPUT_DIR${NC}"
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

  subdomain_enum
  whois_enum

  # ── Empty subdomain output guard ──────────────────────────────────────────
  local _sub_count; _sub_count=$(linecount "$OUTPUT_DIR/subdomains/all_subdomains.txt")
  if [ "$_sub_count" -eq 0 ]; then
    warn "Subdomain enumeration found 0 results — DNS/HTTP modules may produce limited output"
    warn "Continuing with $DOMAIN as fallback target"
  else
    ok "Proceeding with $_sub_count subdomains into DNS & HTTP phases"
  fi

  # ── port_scan runs in background while dns_enum + http_probe run serially ─
  info "Starting port scan in background (parallel with DNS & HTTP probing)..."
  local _port_pid; _port_pid=$(_module_bg port_scan)

  dns_enum
  http_probe

  # ── Wait for the background port scan ─────────────────────────────────────
  _spinner "Waiting for port scan to finish" &
  _SPINNER_PID=$!
  wait "$_port_pid" || true
  kill "$_SPINNER_PID" 2>/dev/null; wait "$_SPINNER_PID" 2>/dev/null
  _SPINNER_PID=""; tput cnorm 2>/dev/null || true; printf "\r\033[K"
  ok "Port scan complete — results in $OUTPUT_DIR/ports/"

  # ── Feed naabu-discovered ports into httpx ────────────────────────────────
  _probe_naabu_ports

  url_discovery
  content_discovery
  vuln_scan
  secret_scan
  take_screenshots
  subdomain_takeover
  generate_summary
}

# ── Quick Recon (applies quick profile, then runs everything) ────────────────
quick_recon() {
  apply_profile quick
  full_recon
}

# ── Custom Recon — pick which modules to run ─────────────────────────────────
custom_recon() {
  local modules=(
    "Subdomain Enumeration:subdomain_enum"
    "DNS Enumeration:dns_enum"
    "Port Scanning:port_scan"
    "HTTP Probing & Tech Detection:http_probe"
    "Content Discovery:content_discovery"
    "URL Discovery:url_discovery"
    "Vulnerability Scanning:vuln_scan"
    "JS Secret Scanning:secret_scan"
    "Screenshots:take_screenshots"
    "Subdomain Takeover Check:subdomain_takeover"
  )

  echo ""
  echo -e "${BOLD}${CYAN}Custom Recon — select modules to run${NC}"
  echo ""

  local selected=()

  for i in "${!modules[@]}"; do
    local label="${modules[$i]%%:*}"
    printf "  [%2d]  %s\n" "$((i+1))" "$label"
  done

  echo ""
  echo -e "  Enter module numbers separated by spaces."
  echo -e "  Example: ${YELLOW}1 2 4 7${NC}  runs Sub Enum + DNS + HTTP + Vuln Scan"
  echo -e "  Enter ${YELLOW}all${NC} to run every module."
  echo ""
  read -rp "$(echo -e "${BOLD}Selection: ${NC}")" selection

  if [ "$selection" = "all" ]; then
    full_recon
    return
  fi

  for num in $selection; do
    if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#modules[@]}" ]; then
      local fn="${modules[$((num-1))]##*:}"
      selected+=("$fn")
    else
      warn "Skipping invalid selection: $num"
    fi
  done

  if [ "${#selected[@]}" -eq 0 ]; then
    err "No valid modules selected."
    return
  fi

  echo ""
  echo -e "${BOLD}Running modules:${NC}"
  for fn in "${selected[@]}"; do
    echo -e "  • ${CYAN}$fn${NC}"
  done
  echo ""
  read -rp "$(echo -e "${BOLD}Proceed? [y/N]: ${NC}")" confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { info "Cancelled."; return; }

  for fn in "${selected[@]}"; do
    "$fn"
  done

  generate_summary
}

# =============================================================================
#  SUMMARY
# =============================================================================

generate_summary() {
  section "SCAN SUMMARY"
  local summary="$OUTPUT_DIR/00_summary.txt"

  # ── Scan duration ──────────────────────────────────────────────────────────
  local _elapsed=$(( SECONDS - SCAN_START ))
  local _dur
  if [ "$_elapsed" -ge 3600 ]; then
    _dur="$(( _elapsed / 3600 ))h$(( (_elapsed % 3600) / 60 ))m$(( _elapsed % 60 ))s"
  elif [ "$_elapsed" -ge 60 ]; then
    _dur="$(( _elapsed / 60 ))m$(( _elapsed % 60 ))s"
  else
    _dur="${_elapsed}s"
  fi

  # ── Open ports ────────────────────────────────────────────────────────────
  local _ports_count; _ports_count=$(linecount "$OUTPUT_DIR/ports/naabu_open.txt")
  if [ "$_ports_count" -eq 0 ]; then
    _ports_count=$(grep -cE '[0-9]+/open' "$OUTPUT_DIR/ports/nmap_quick.gnmap" 2>/dev/null || echo "0")
  fi

  # ── WAF detection ─────────────────────────────────────────────────────────
  local _waf
  _waf=$(grep -oiE 'behind [A-Za-z0-9 ]+|No WAF detected' \
    "$OUTPUT_DIR/http/waf.txt" 2>/dev/null | head -1)
  [ -z "$_waf" ] && _waf="not checked"

  # ── Top tech stack from httpx tech-detect output ──────────────────────────
  local _tech
  _tech=$(grep -oE '\[[A-Za-z][^]]+\]' "$OUTPUT_DIR/http/live_hosts.txt" 2>/dev/null \
    | tr -d '[]' | tr ',' '\n' \
    | grep -vE '^[0-9]|^$' \
    | sort | uniq -c | sort -rn | head -5 \
    | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
  [ -z "$_tech" ] && _tech="not available"

  # ── Failed tools ──────────────────────────────────────────────────────────
  local _failed_count; _failed_count=$(linecount "$OUTPUT_DIR/.failed_tools")

  # ── Top critical findings ─────────────────────────────────────────────────
  local _top_findings=""
  if [ -f "$OUTPUT_DIR/vulns/nuclei_crit_high.txt" ] \
      && [ "$(linecount "$OUTPUT_DIR/vulns/nuclei_crit_high.txt")" -gt 0 ]; then
    _top_findings=$(head -5 "$OUTPUT_DIR/vulns/nuclei_crit_high.txt" 2>/dev/null)
  fi

  {
    printf '=%.0s' {1..60}; echo
    printf "  RECON SUMMARY — %s\n" "$DOMAIN"
    printf "  Profile    : %s\n" "$CURRENT_PROFILE"
    printf "  Completed  : %s\n" "$(date)"
    printf "  Duration   : %s\n" "$_dur"
    printf '=%.0s' {1..60}; echo
    echo ""
    printf "  %-34s %s\n" "Subdomains discovered:"  "$(linecount "$OUTPUT_DIR/subdomains/all_subdomains.txt")"
    printf "  %-34s %s\n" "Subdomains resolved:"    "$(linecount "$OUTPUT_DIR/dns/resolved.txt")"
    printf "  %-34s %s\n" "Live HTTP hosts:"        "$(linecount "$OUTPUT_DIR/http/live_hosts.txt")"
    printf "  %-34s %s\n" "Open ports discovered:"  "$_ports_count"
    printf "  %-34s %s\n" "Total URLs discovered:"  "$(linecount "$OUTPUT_DIR/urls/all_urls.txt")"
    printf "  %-34s %s\n" "JS files found:"         "$(linecount "$OUTPUT_DIR/urls/js_files.txt")"
    echo ""
    printf "  %-34s %s\n" "Critical vulns:"         "$(linecount "$OUTPUT_DIR/vulns/nuclei_critical.txt")"
    printf "  %-34s %s\n" "High vulns:"             "$(linecount "$OUTPUT_DIR/vulns/nuclei_high.txt")"
    printf "  %-34s %s\n" "CVEs identified:"        "$(linecount "$OUTPUT_DIR/vulns/nuclei_cves.txt")"
    printf "  %-34s %s\n" "Full nuclei findings:"   "$(linecount "$OUTPUT_DIR/vulns/nuclei_full.txt")"
    printf "  %-34s %s\n" "Potential takeovers:"    "$(linecount "$OUTPUT_DIR/takeover/takeover_results.txt")"
    echo ""
    printf "  %-34s %s\n" "WAF detected:"           "$_waf"
    printf "  %-34s %s\n" "Top tech stack:"         "$_tech"
    [ "$_failed_count" -gt 0 ] && \
      printf "  %-34s %s\n" "Failed/timed-out tools:" "$_failed_count (see .failed_tools)"
    echo ""
    if [ -n "$_top_findings" ]; then
      echo "  Top critical/high findings:"
      echo "$_top_findings" | while IFS= read -r line; do
        printf "    %s\n" "$line"
      done
      echo ""
    fi
    echo "  Output : $OUTPUT_DIR"
    echo "  Log    : $LOG_FILE"
    printf '=%.0s' {1..60}; echo
  } | tee "$summary"

  ok "Summary → $summary"
  [ "$_failed_count" -gt 0 ] && \
    warn "$_failed_count tool(s) failed or timed out — review $OUTPUT_DIR/.failed_tools"
}

# =============================================================================
#  PROFILE SELECTION MENU
# =============================================================================

select_profile() {
  echo ""
  echo -e "${BOLD}${CYAN}Select a Profile${NC}"
  echo ""
  echo -e "  ${YELLOW}1${NC}  ${BOLD}Quick${NC}          Fast scan — subfinder, httpx, nuclei (critical/high)"
  echo -e "               ~10–20 min on a typical scope"
  echo ""
  echo -e "  ${YELLOW}2${NC}  ${BOLD}Standard${NC}  ${GREEN}[✓]${NC}  Balanced — recommended for most engagements"
  echo -e "               subfinder+amass, naabu+nmap, ffuf+gobuster, nuclei full, gowitness"
  echo ""
  echo -e "  ${YELLOW}3${NC}  ${BOLD}Comprehensive${NC}  All tools enabled — maximum coverage, maximum time"
  echo -e "               Includes nikto, feroxbuster, gospider, aquatone, trufflehog..."
  echo ""
  read -rp "$(echo -e "${BOLD}Profile [1/2/3] (Enter to keep '${CURRENT_PROFILE}'): ${NC}")" pr
  case "$pr" in
    1) apply_profile quick         ;;
    2) apply_profile standard      ;;
    3) apply_profile comprehensive ;;
    '') info "Keeping profile: $CURRENT_PROFILE" ;;
    *) err "Invalid selection"     ;;
  esac
}

# =============================================================================
#  IP LIST SCAN  (-i flag or menu option I)
# =============================================================================

scan_ip_list() {
  local target_file="$1"
  local out="$OUTPUT_DIR/ports"

  section "IP / FQDN LIST SCAN"

  # ── Validate input ──────────────────────────────────────────────────────────
  if [ ! -f "$target_file" ]; then
    err "File not found: $target_file"
    return 1
  fi

  local total; total=$(grep -c '[^[:space:]]' "$target_file" 2>/dev/null || echo 0)
  ok "Input file : $target_file"
  ok "Targets    : $total"

  # ── Choose scan depth ───────────────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Scan depth:${NC}"
  echo -e "  ${YELLOW}1${NC}  Quick     — host discovery + top-1000 ports + service detection"
  echo -e "  ${YELLOW}2${NC}  Standard  — host discovery + full 65535 ports + service + default scripts ${GREEN}[recommended]${NC}"
  echo -e "  ${YELLOW}3${NC}  Deep      — standard + NSE vuln scripts + targeted service enum (SMB/HTTP/SSH/RDP/FTP)"
  echo ""
  read -rp "$(echo -e "${BOLD}Depth [1/2/3, Enter for Standard]: ${NC}")" depth
  [ -z "$depth" ] && depth=2

  local TIMING="-T4"

  # ── Phase 1: Host Discovery ─────────────────────────────────────────────────
  section "Phase 1 — Host Discovery"
  info "Probing with ICMP echo/timestamp + TCP SYN/ACK against common ports..."
  cmd_echo "nmap -sn $TIMING -PE -PP -PS21,22,25,80,443,445,3389,8080,8443 -PA80,443 -iL $target_file"

  nmap -sn $TIMING \
    -PE -PP \
    -PS21,22,25,53,80,443,445,3389,8080,8443 \
    -PA80,443 \
    -iL "$target_file" \
    -oA "$out/phase1_discovery" \
    --reason 2>>"$LOG_FILE" || true

  # Extract live hosts from grepable output
  if [ -f "$out/phase1_discovery.gnmap" ]; then
    grep "Status: Up" "$out/phase1_discovery.gnmap" \
      | awk '{print $2}' | sort -u > "$out/live_hosts.txt" || true
  fi

  local live; live=$(linecount "$out/live_hosts.txt")
  ok "Live hosts : $live / $total"

  if [ "$live" -eq 0 ]; then
    warn "No live hosts via discovery probes (targets may block ICMP/probe ports)."
    warn "Falling back to scanning original target list directly..."
    cp "$target_file" "$out/live_hosts.txt"
    live=$total
  fi

  # ── Phase 2: Port Scanning ──────────────────────────────────────────────────
  if [ "$depth" -eq 1 ]; then
    section "Phase 2 — Fast Port Scan (top 1000)"
    cmd_echo "nmap $TIMING --min-rate 1000 --open --reason -iL live_hosts.txt"
    nmap $TIMING \
      --min-rate 1000 --open --reason \
      -iL "$out/live_hosts.txt" \
      -oA "$out/phase2_ports" 2>>"$LOG_FILE" || true
  else
    section "Phase 2 — Full Port Scan (all 65535)"
    info "Scanning all ports — this may take a while for large scopes..."
    cmd_echo "nmap -p- $TIMING --min-rate 2000 --open --reason -iL live_hosts.txt"
    nmap -p- $TIMING \
      --min-rate 2000 --open --reason \
      -iL "$out/live_hosts.txt" \
      -oA "$out/phase2_ports" 2>>"$LOG_FILE" || true
  fi

  # Extract unique open ports across all hosts
  local open_ports=""
  if [ -f "$out/phase2_ports.gnmap" ]; then
    open_ports=$(grep -oE '[0-9]+/open' "$out/phase2_ports.gnmap" \
      | cut -d/ -f1 | sort -un | tr '\n' ',' | sed 's/,$//' 2>/dev/null) || true
  fi

  local port_count; port_count=$(echo "$open_ports" | tr ',' '\n' | grep -c '[0-9]' 2>/dev/null || echo 0)
  ok "Unique open ports : $port_count"
  [ -n "$open_ports" ] && ok "Ports : $open_ports"

  if [ -z "$open_ports" ]; then
    warn "No open ports found. Check connectivity and firewall rules."
    return
  fi

  # ── Phase 3: Service & Version Detection ────────────────────────────────────
  section "Phase 3 — Service & Version Detection"
  info "Running -sV and default scripts (-sC) on all open ports..."
  cmd_echo "nmap -sV --version-intensity 5 -sC -p $open_ports --open -iL live_hosts.txt"

  nmap -sV --version-intensity 5 \
    -sC \
    -p "$open_ports" \
    --open \
    -iL "$out/live_hosts.txt" \
    -oA "$out/phase3_services" 2>>"$LOG_FILE" || true

  ok "Service scan complete → $out/phase3_services.*"

  # ── Phase 4 (Deep only): NSE Targeted Scripts ───────────────────────────────
  if [ "$depth" -ge 3 ]; then
    section "Phase 4 — NSE Vulnerability & Service Enumeration"

    # Generic vuln scripts across all open ports
    info "Running NSE vuln scripts on all open ports..."
    cmd_echo "nmap --script vuln -p $open_ports -iL live_hosts.txt"
    nmap --script vuln \
      -p "$open_ports" \
      -iL "$out/live_hosts.txt" \
      -oA "$out/phase4_vuln" 2>>"$LOG_FILE" || true

    # SMB (139, 445)
    if echo "$open_ports" | grep -qE '(^|,)(139|445)(,|$)'; then
      info "SMB detected — running SMB enumeration & vuln scripts..."
      cmd_echo "nmap --script smb-vuln*,smb-enum-shares,smb-enum-users,smb-security-mode -p 139,445"
      nmap --script "smb-vuln*,smb-enum-shares,smb-enum-users,smb-security-mode,smb2-security-mode" \
        -p 139,445 \
        -iL "$out/live_hosts.txt" \
        -oA "$out/phase4_smb" 2>>"$LOG_FILE" || true
    fi

    # HTTP/HTTPS (80, 443, 8080, 8443, 8888, 9090)
    if echo "$open_ports" | grep -qE '(^|,)(80|443|8080|8443|8888|9090)(,|$)'; then
      info "HTTP ports detected — running HTTP enumeration scripts..."
      cmd_echo "nmap --script http-title,http-headers,http-methods,http-auth-finder,http-robots.txt"
      nmap --script "http-title,http-headers,http-methods,http-auth-finder,http-robots.txt" \
        -p 80,443,8080,8443,8888,9090 \
        -iL "$out/live_hosts.txt" \
        -oA "$out/phase4_http" 2>>"$LOG_FILE" || true
    fi

    # FTP (21)
    if echo "$open_ports" | grep -qE '(^|,)21(,|$)'; then
      info "FTP detected — running FTP scripts..."
      nmap --script "ftp-anon,ftp-bounce,ftp-syst,ftp-vuln*" \
        -p 21 -iL "$out/live_hosts.txt" \
        -oA "$out/phase4_ftp" 2>>"$LOG_FILE" || true
    fi

    # SSH (22)
    if echo "$open_ports" | grep -qE '(^|,)22(,|$)'; then
      info "SSH detected — running SSH scripts..."
      nmap --script "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos" \
        -p 22 -iL "$out/live_hosts.txt" \
        -oA "$out/phase4_ssh" 2>>"$LOG_FILE" || true
    fi

    # RDP (3389)
    if echo "$open_ports" | grep -qE '(^|,)3389(,|$)'; then
      info "RDP detected — running RDP scripts..."
      nmap --script "rdp-enum-encryption,rdp-vuln-ms12-020" \
        -p 3389 -iL "$out/live_hosts.txt" \
        -oA "$out/phase4_rdp" 2>>"$LOG_FILE" || true
    fi

    # MSSQL (1433)
    if echo "$open_ports" | grep -qE '(^|,)1433(,|$)'; then
      info "MSSQL detected — running MSSQL scripts..."
      nmap --script "ms-sql-info,ms-sql-empty-password,ms-sql-config" \
        -p 1433 -iL "$out/live_hosts.txt" \
        -oA "$out/phase4_mssql" 2>>"$LOG_FILE" || true
    fi

    # SNMP (161)
    if echo "$open_ports" | grep -qE '(^|,)161(,|$)'; then
      info "SNMP detected — running SNMP scripts..."
      nmap --script "snmp-info,snmp-sysdescr,snmp-brute" \
        -sU -p 161 -iL "$out/live_hosts.txt" \
        -oA "$out/phase4_snmp" 2>>"$LOG_FILE" || true
    fi

    ok "Deep scan complete → $out/phase4_*"
  fi

  # ── Per-host port summary ────────────────────────────────────────────────────
  section "Per-Host Results"
  if [ -f "$out/phase3_services.nmap" ]; then
    grep -E "^Nmap scan report|^[0-9]+/tcp|^[0-9]+/udp" \
      "$out/phase3_services.nmap" 2>/dev/null | \
    while IFS= read -r line; do
      if echo "$line" | grep -q "^Nmap scan report"; then
        echo ""
        echo -e "${BOLD}${CYAN}$line${NC}"
      else
        echo -e "  ${GREEN}$line${NC}"
      fi
    done
  fi

  # ── Summary ──────────────────────────────────────────────────────────────────
  section "IP SCAN SUMMARY"
  local depth_label
  case "$depth" in
    1) depth_label="Quick"    ;;
    2) depth_label="Standard" ;;
    3) depth_label="Deep"     ;;
    *) depth_label="Unknown"  ;;
  esac

  local summary="$OUTPUT_DIR/00_ipscan_summary.txt"
  {
    printf '=%.0s' {1..52}; echo
    printf "  IP LIST SCAN SUMMARY\n"
    printf "  Input file  : %s\n" "$target_file"
    printf "  Scan depth  : %s\n" "$depth_label"
    printf "  Completed   : %s\n" "$(date)"
    printf '=%.0s' {1..52}; echo
    echo ""
    printf "  %-30s %s\n" "Total targets:"    "$total"
    printf "  %-30s %s\n" "Live hosts:"       "$live"
    printf "  %-30s %s\n" "Open port count:"  "$port_count"
    printf "  %-30s %s\n" "Open ports:"       "$open_ports"
    echo ""
    echo "  Output files:"
    ls "$out"/phase*.nmap 2>/dev/null | while read -r f; do
      printf "    %s\n" "$f"
    done
    printf '=%.0s' {1..52}; echo
  } | tee "$summary"

  ok "Results  → $out/"
  ok "Summary  → $summary"
}

# =============================================================================
#  MAIN MENU
# =============================================================================

menu() {
  while true; do
    local _api_count; _api_count=$(count_set_keys)
    echo ""
    echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}│  Recon Suite                                             │${NC}"
    echo -e "${BOLD}${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    printf "${BOLD}${CYAN}│  Target  : ${GREEN}%-46s${CYAN}│${NC}\n" "$DOMAIN"
    printf "${BOLD}${CYAN}│  Profile : ${YELLOW}%-46s${CYAN}│${NC}\n" "$CURRENT_PROFILE"
    printf "${BOLD}${CYAN}│  Wordlist: ${MAGENTA}%-46s${CYAN}│${NC}\n" "${WORDLIST:+$(basename "$WORDLIST")}${WORDLIST:-not set — auto-detect or press W}"
    printf "${BOLD}${CYAN}│  API Keys: ${YELLOW}%-46s${CYAN}│${NC}\n" "${_api_count}/7 set  (K to configure)"
    printf "${BOLD}${CYAN}│  Output  : ${DIM}%-46s${CYAN}│${NC}\n" "$OUTPUT_DIR"
    echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "  ${BOLD}── Run Modes ──────────────────────────────────${NC}"
    echo -e "   ${YELLOW}A${NC}  Quick Recon       (fast profile, all modules)"
    echo -e "   ${YELLOW}B${NC}  Full Recon        (current profile, all modules)"
    echo -e "   ${YELLOW}C${NC}  Custom Recon      (pick which modules to run)"
    echo -e "   ${YELLOW}I${NC}  IP List Scan      (nmap against a file of IPs/FQDNs)"
    echo ""
    echo -e "  ${BOLD}── Individual Modules ─────────────────────────${NC}"
    echo -e "   ${YELLOW}1${NC}  Subdomain Enumeration"
    echo -e "   ${YELLOW}2${NC}  DNS Enumeration"
    echo -e "   ${YELLOW}3${NC}  Port Scanning"
    echo -e "   ${YELLOW}4${NC}  HTTP Probing & Tech Detection"
    echo -e "   ${YELLOW}5${NC}  Content Discovery  (dir fuzzing)"
    echo -e "   ${YELLOW}6${NC}  URL Discovery      (archives + crawling)"
    echo -e "   ${YELLOW}7${NC}  Vulnerability Scanning  (nuclei)"
    echo -e "   ${YELLOW}8${NC}  Screenshots"
    echo -e "   ${YELLOW}9${NC}  Subdomain Takeover Check"
    echo -e "  ${YELLOW}10${NC}  JS Secret Scanning"
    echo ""
    echo -e "  ${BOLD}── Configuration ──────────────────────────────${NC}"
    echo -e "   ${YELLOW}P${NC}  Set Profile        (Quick / Standard / Comprehensive)"
    echo -e "   ${YELLOW}T${NC}  Configure Tools    (toggle individual tools on/off)"
    echo -e "   ${YELLOW}W${NC}  Set Wordlist       (for ffuf / gobuster / feroxbuster)"
    echo -e "   ${YELLOW}K${NC}  API Keys           (subfinder/findomain/gau)"
    echo -e "   ${YELLOW}D${NC}  Install Dependencies  (run ./install.sh for auto-install)"
    echo -e "   ${YELLOW}G${NC}  Generate Summary"
    echo -e "   ${YELLOW}X${NC}  Change Target"
    echo -e "   ${YELLOW}0${NC}  Exit"
    echo ""

    read -rp "$(echo -e "${BOLD}Select: ${NC}")" choice

    case "$choice" in
      [Aa])  quick_recon ;;
      [Bb])  full_recon ;;
      [Cc])  custom_recon ;;
      [Ii])
             read -rp "Path to IP/FQDN list file: " ifile
             if [ -n "$ifile" ]; then
               scan_ip_list "$ifile"
             else
               err "No file specified."
             fi
             ;;
      1)     subdomain_enum ;;
      2)     dns_enum ;;
      3)
             read -rp "Target IP/host [default: $DOMAIN]: " pt
             port_scan "${pt:-$DOMAIN}"
             ;;
      4)
             read -rp "Subdomains file [default: $OUTPUT_DIR/subdomains/all_subdomains.txt]: " ph
             http_probe "${ph:-$OUTPUT_DIR/subdomains/all_subdomains.txt}"
             ;;
      5)
             read -rp "Target URL [default: https://$DOMAIN]: " pu
             content_discovery "${pu:-https://$DOMAIN}"
             ;;
      6)     url_discovery ;;
      7)
             read -rp "Live hosts file [default: $OUTPUT_DIR/http/live_hosts.txt]: " pv
             vuln_scan "${pv:-$OUTPUT_DIR/http/live_hosts.txt}"
             ;;
      8)
             read -rp "Live hosts file [default: $OUTPUT_DIR/http/live_hosts.txt]: " ps
             take_screenshots "${ps:-$OUTPUT_DIR/http/live_hosts.txt}"
             ;;
      9)
             read -rp "Subdomains file [default: $OUTPUT_DIR/subdomains/all_subdomains.txt]: " pk
             subdomain_takeover "${pk:-$OUTPUT_DIR/subdomains/all_subdomains.txt}"
             ;;
      10)    secret_scan ;;
      [Pp])  select_profile ;;
      [Tt])  configure_tools ;;
      [Ww])  select_wordlist ;;
      [Kk])  configure_api_keys ;;
      [Dd])  install_deps ;;
      [Gg])  generate_summary ;;
      [Xx])
             read -rp "New target domain: " DOMAIN
             DOMAIN=$(echo "$DOMAIN" | sed 's|^https\?://||;s|/.*||')
             setup
             ;;
      0)
             ok "Exiting. Results → ${BOLD}$OUTPUT_DIR${NC}"
             break
             ;;
      *)     err "Invalid option" ;;
    esac
  done
}

# =============================================================================
#  ENTRY POINT
# =============================================================================

usage() {
  echo ""
  echo -e "${BOLD}Usage:${NC}"
  echo "  ./Rec0n-Zer0.sh [options] [domain]"
  echo ""
  echo -e "${BOLD}Options:${NC}"
  echo "  -d <domain>  Target domain for recon (e.g. example.com)"
  echo "  -i <file>    IP/FQDN list for port scan — one address or hostname per line"
  echo "  -e           Check if all dependencies are installed (read-only status report)"
  echo "  -h           Show this help"
  echo ""
  echo -e "${BOLD}Modes:${NC}"
  echo "  Domain recon only    ./Rec0n-Zer0.sh -d example.com"
  echo "  IP scan only         ./Rec0n-Zer0.sh -i targets.txt"
  echo "  Combined (both)      ./Rec0n-Zer0.sh -d example.com -i targets.txt"
  echo "    → runs full interactive domain recon first; IP scan starts automatically"
  echo "      when you exit the menu (press 0)"
  echo ""
  echo -e "${BOLD}Examples:${NC}"
  echo "  ./Rec0n-Zer0.sh                                  # prompt for domain"
  echo "  ./Rec0n-Zer0.sh example.com                      # domain recon (interactive)"
  echo "  ./Rec0n-Zer0.sh -d example.com                   # domain recon via flag"
  echo "  ./Rec0n-Zer0.sh -i targets.txt                   # IP list scan only"
  echo "  ./Rec0n-Zer0.sh -d example.com -i targets.txt    # domain recon then IP scan"
  echo "  ./Rec0n-Zer0.sh -e                               # check if all required tools are installed"
  echo "  ./install.sh                                     # install all required tools"
  echo ""
  echo -e "${BOLD}Environment overrides:${NC}"
  echo "  WORDLIST=/path/to/list.txt         # custom wordlist for content discovery"
  echo "  ENABLE_AMASS=0                     # disable a specific tool"
  echo "  API_SHODAN=abc123                  # pass API key inline (not saved)"
  echo ""
  echo -e "${BOLD}API keys (optional — tools work without them):${NC}"
  echo "  Press K in the menu to add/save keys interactively."
  echo "  Saved to: ~/.config/recon/api_keys.conf (chmod 600)"
  echo "  Keys improve coverage for: subfinder, findomain, gau"
  echo ""
}

main() {
  banner

  # Load saved API keys from config file (silently, no error if missing)
  load_api_keys

  # ── Activate Python venv and Go bin so installed tools are discoverable ────
  [ -d "$RECON_VENV/bin" ] && [[ ":$PATH:" != *":$RECON_VENV/bin:"* ]] \
    && export PATH="$RECON_VENV/bin:$PATH"
  local _go_bin="$TOOLS_DIR/go/bin"
  [ -d "$_go_bin" ] && [[ ":$PATH:" != *":$_go_bin:"* ]] \
    && export PATH="$_go_bin:$PATH"

  local input_file=""
  local domain_arg=""
  local run_install_deps=0

  # ── Parse flags ─────────────────────────────────────────────────────────────
  while getopts ":i:d:he" opt; do
    case "$opt" in
      i) input_file="$OPTARG" ;;
      d) domain_arg="$OPTARG" ;;
      h) usage; exit 0 ;;
      e) run_install_deps=1 ;;
      :) err "Option -$OPTARG requires an argument."; usage; exit 1 ;;
      \?) err "Unknown option: -$OPTARG"; usage; exit 1 ;;
    esac
  done
  shift $((OPTIND - 1))

  # ── Check deps mode (-e) — read-only status report, no installs ─────────────
  if [ "$run_install_deps" -eq 1 ]; then
    check_deps
    exit $?
  fi

  # Remaining positional arg treated as domain
  [ -z "$domain_arg" ] && domain_arg="${1:-}"

  # ── IP List Scan only (no -d / domain given) ────────────────────────────────
  if [ -n "$input_file" ] && [ -z "$domain_arg" ]; then
    if [ ! -f "$input_file" ]; then
      err "File not found: $input_file"
      exit 1
    fi
    DOMAIN=$(basename "$input_file" | sed 's/\.[^.]*$//')
    ok "Mode   : ${BOLD}IP List Scan${NC}"
    ok "File   : ${BOLD}$input_file${NC}"
    ok "Prefix : ${BOLD}$DOMAIN${NC}"
    setup
    scan_ip_list "$input_file"
    exit 0
  fi

  # ── Validate IP file early when running in combined mode ────────────────────
  if [ -n "$input_file" ] && [ ! -f "$input_file" ]; then
    err "File not found: $input_file"
    exit 1
  fi

  # ── Domain Recon (+ optional follow-up IP scan when -i is also given) ───────
  if [ -n "$domain_arg" ]; then
    DOMAIN="$domain_arg"
  else
    read -rp "$(echo -e "${BOLD}Enter target domain (e.g., example.com): ${NC}")" DOMAIN
  fi

  DOMAIN=$(echo "$DOMAIN" | sed 's|^https\?://||;s|/.*||')

  if [ -z "$DOMAIN" ]; then
    err "Domain cannot be empty."
    exit 1
  fi

  # Validate domain: only allow valid hostname characters
  if ! printf '%s' "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$'; then
    err "Invalid domain format: '$DOMAIN'"
    err "Expected format: example.com or sub.example.com"
    exit 1
  fi

  if [ -n "$input_file" ]; then
    ok "Mode   : ${BOLD}Combined (Domain Recon → IP List Scan)${NC}"
  else
    ok "Mode   : ${BOLD}Domain Recon${NC}"
  fi
  ok "Target : ${BOLD}$DOMAIN${NC}"
  [ -n "$input_file" ] && ok "IP File: ${BOLD}$input_file${NC}"
  setup

  # Optionally select profile at startup
  echo ""
  echo -e "${BOLD}Select starting profile:${NC}"
  echo -e "  ${YELLOW}1${NC} Quick   ${YELLOW}2${NC} Standard (default)   ${YELLOW}3${NC} Comprehensive"
  read -rp "$(echo -e "${BOLD}Profile [1/2/3, Enter for Standard]: ${NC}")" startup_profile
  case "$startup_profile" in
    1) apply_profile quick         ;;
    3) apply_profile comprehensive ;;
    *) apply_profile standard      ;;
  esac

  menu

  # ── Follow-up IP List Scan (combined mode only) ──────────────────────────────
  if [ -n "$input_file" ]; then
    section "IP List Scan"
    ok "Mode   : ${BOLD}IP List Scan${NC}"
    ok "File   : ${BOLD}$input_file${NC}"
    scan_ip_list "$input_file"
  fi
}

# Run main only when executed directly — not when sourced by recon_v2.sh
# (if-form is used so set -e doesn't exit on the false condition)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then main "$@"; fi
