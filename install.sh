#!/usr/bin/env bash
# =============================================================================
#  Rec0n-Zer0 — install.sh
#  Installs all required tools into Rec0n-Zer0-Tools/ next to this script.
#
#  Usage:
#    ./install.sh              # full install
#    ./install.sh --check      # check status only (no installs)
#    ./install.sh --uninstall  # remove all installed Go/pip tools
#
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

info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }
has()   { command -v "$1" &>/dev/null; }

# ── Config — must match Rec0n-Zer0.sh ─────────────────────────────────────────
RECON_VENV="$TOOLS_DIR/venv"

# ── Dependency registry — keep in sync with Rec0n-Zer0.sh DEPS[] ──────────────
# Format: "binary:method:value"
#   system  — OS package manager (apt / dnf / yum)
#   go      — go install <value>
#   pip     — pip install inside venv
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
  "rustscan:system:rustscan"
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
  "trufflehog:go:github.com/trufflesecurity/trufflehog/v3@latest"
  "gitleaks:go:github.com/gitleaks/gitleaks/v8@latest"
)

# System packages that can be removed during uninstall
SYSTEM_PKGS=(
  amass findomain dnsutils nmap rustscan masscan
  ffuf gobuster feroxbuster dirsearch nikto
)

# ── Package manager detection ──────────────────────────────────────────────────
PKG_MGR=""
SUDO=""

detect_pkg_manager() {
  local os_type
  os_type=$(uname -s)
  case "$os_type" in
    Linux)
      if has apt-get;   then PKG_MGR="apt"
      elif has dnf;     then PKG_MGR="dnf"
      elif has yum;     then PKG_MGR="yum"
      else
        err "No supported package manager found (apt / dnf / yum)."
        exit 1
      fi
      [ "$(id -u)" -ne 0 ] && SUDO="sudo" || SUDO=""
      ok "OS: Linux  |  package manager: $PKG_MGR"
      ;;
    *)
      err "Unsupported OS: $os_type. This tool is designed for Kali Linux."
      exit 1
      ;;
  esac
}

# Resolve distro-specific package names
_resolve_pkg() {
  local pkg="$1"
  case "$pkg" in
    dig)
      case "$PKG_MGR" in
        apt)     echo "dnsutils" ;;
        dnf|yum) echo "bind-utils" ;;
        *)       echo "$pkg" ;;
      esac
      ;;
    *) echo "$pkg" ;;
  esac
}

pkg_install() {
  local pkg; pkg=$(_resolve_pkg "$1")
  case "$PKG_MGR" in
    apt)  $SUDO apt-get install -y "$pkg" 2>&1 | tail -5 ;;
    dnf)  $SUDO dnf install -y "$pkg" 2>&1 | tail -5 ;;
    yum)  $SUDO yum install -y "$pkg" 2>&1 | tail -5 ;;
  esac
}

# =============================================================================
#  STEP 1 — PYTHON3 VIRTUAL ENVIRONMENT
# =============================================================================

setup_venv() {
  echo ""
  echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════╗${NC}"
  printf "${BOLD}${MAGENTA}║  %-44s║${NC}\n" "Python3 Virtual Environment"
  echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════╝${NC}"
  echo ""

  # python3 must exist
  if ! has python3; then
    warn "python3 not found — installing..."
    case "$PKG_MGR" in
      apt)  $SUDO apt-get install -y python3 python3-pip python3-venv ;;
      dnf)  $SUDO dnf install -y python3 python3-pip ;;
      yum)  $SUDO yum install -y python3 python3-pip ;;
    esac || { err "Failed to install python3."; exit 1; }
  fi
  ok "python3 : $(python3 --version 2>&1)"

  # pip3 must exist
  if ! has pip3 && ! python3 -m pip --version &>/dev/null 2>&1; then
    warn "pip3 not found — bootstrapping via ensurepip..."
    python3 -m ensurepip --upgrade 2>/dev/null || true
    if ! has pip3; then
      case "$PKG_MGR" in
        apt) $SUDO apt-get install -y python3-pip 2>/dev/null || true ;;
        dnf) $SUDO dnf install -y python3-pip 2>/dev/null || true ;;
        yum) $SUDO yum install -y python3-pip 2>/dev/null || true ;;
      esac
    fi
  fi

  # python3-venv module
  if ! python3 -c "import venv" 2>/dev/null; then
    warn "python3 venv module not found — installing python3-venv..."
    case "$PKG_MGR" in
      apt)  $SUDO apt-get install -y python3-venv 2>/dev/null || true ;;
      dnf)  $SUDO dnf install -y python3-venv 2>/dev/null || true ;;
      yum)  $SUDO yum install -y python3-venv 2>/dev/null || true ;;
    esac
    if ! python3 -c "import venv" 2>/dev/null; then
      err "Cannot create Python venv — python3-venv unavailable."
      exit 1
    fi
  fi

  # Create venv inside TOOLS_DIR
  mkdir -p "$TOOLS_DIR"
  if [ ! -d "$RECON_VENV" ]; then
    info "Creating Python venv at $RECON_VENV ..."
    python3 -m venv "$RECON_VENV" || { err "Failed to create venv."; exit 1; }
    "$RECON_VENV/bin/pip" install --quiet --upgrade pip 2>/dev/null || true
    ok "Python venv created → $RECON_VENV"
  else
    ok "Python venv exists  → $RECON_VENV"
  fi

  # Always add venv to PATH for this session
  export PATH="$RECON_VENV/bin:$PATH"
  ok "Venv active         → $(python3 --version 2>&1)  |  pip $(pip --version 2>&1 | awk '{print $2}')"
}

# =============================================================================
#  STEP 2 — GO
# =============================================================================

setup_go() {
  echo ""
  echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════╗${NC}"
  printf "${BOLD}${MAGENTA}║  %-44s║${NC}\n" "Go Installation"
  echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════╝${NC}"
  echo ""

  if ! has go; then
    info "Go not found — installing via package manager..."
    case "$PKG_MGR" in
      apt)  $SUDO apt-get install -y golang-go ;;
      dnf)  $SUDO dnf install -y golang ;;
      yum)  $SUDO yum install -y golang ;;
    esac || { err "Failed to install Go."; return 1; }
    ok "Go installed."
  else
    ok "Go : $(go version 2>/dev/null)"
  fi

  # Point GOPATH and GOBIN at the tools directory so binaries land there.
  # GOBIN takes precedence over GOPATH/bin — set both to be explicit.
  export GOPATH="$TOOLS_DIR/go"
  export GOBIN="$TOOLS_DIR/go/bin"
  mkdir -p "$GOBIN" 2>/dev/null || true
  [[ ":$PATH:" != *":$GOBIN:"* ]] && export PATH="$GOBIN:$PATH"
  ok "GOPATH → $GOPATH"
  ok "GOBIN  → $GOBIN"

  # CGO build dependency (naabu uses gopacket/libpcap)
  info "Ensuring CGO build dependency (libpcap-dev)..."
  case "$PKG_MGR" in
    apt)  $SUDO apt-get install -y libpcap-dev 2>/dev/null | tail -2 || true ;;
    dnf)  $SUDO dnf install -y libpcap-devel 2>/dev/null | tail -2 || true ;;
    yum)  $SUDO yum install -y libpcap-devel 2>/dev/null | tail -2 || true ;;
  esac

  # Fix Go module proxy DNS if unreachable
  if ! getent hosts proxy.golang.org >/dev/null 2>&1; then
    warn "Go module proxy DNS unreachable — checking /etc/resolv.conf..."
    if ! grep -q 'nameserver 8.8.8.8' /etc/resolv.conf 2>/dev/null; then
      warn "Adding 8.8.8.8 as fallback nameserver..."
      local _tmp; _tmp=$(mktemp)
      { echo "nameserver 8.8.8.8"; cat /etc/resolv.conf; } > "$_tmp" \
        && $SUDO mv "$_tmp" /etc/resolv.conf \
        && ok "Added 8.8.8.8 to /etc/resolv.conf" \
        || warn "Could not update /etc/resolv.conf — go install may fail for some modules"
    fi
  else
    ok "Go module proxy DNS : OK"
  fi
}

# =============================================================================
#  STEP 3 — DISK SPACE CHECK
# =============================================================================

check_disk_space() {
  # -P (POSIX) prevents line-wrapping for long device names
  local _avail_kb _avail_mb
  _avail_kb=$(df -Pk "$SCRIPT_DIR" 2>/dev/null | awk 'NR==2 {print $4}') || _avail_kb=0
  _avail_mb=$(( _avail_kb / 1024 ))
  if [ "$_avail_mb" -lt 2000 ]; then
    warn "Low disk space: ${_avail_mb}MB free on $SCRIPT_DIR (Go builds need ~2 GB)"
    warn "Large tools (naabu, nuclei, trufflehog) may fail to compile."
    warn "Free up space or run: go clean -cache && go clean -modcache"
  else
    ok "Disk space: ${_avail_mb}MB available on $SCRIPT_DIR"
  fi
}

# =============================================================================
#  STEP 4 — INSTALL ALL TOOLS
# =============================================================================

install_all_tools() {
  echo ""
  echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════╗${NC}"
  printf "${BOLD}${MAGENTA}║  %-44s║${NC}\n" "Tool Installation"
  echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════╝${NC}"
  echo ""
  info "Go tools  → $TOOLS_DIR/go/bin"
  info "Pip tools → $TOOLS_DIR/venv/bin"
  info "Scanning ${#DEPS[@]} tool dependencies..."
  echo ""

  local installed_count=0
  local skipped_count=0
  local failed_count=0
  local failed_tools=()

  for dep in "${DEPS[@]}"; do
    local tool="${dep%%:*}"
    local remainder="${dep#*:}"
    local method="${remainder%%:*}"
    local value="${remainder#*:}"

    # For go tools check TOOLS_DIR directly — has() would find system-wide
    # versions in /usr/bin and incorrectly mark them as already installed.
    local already_installed=0
    case "$method" in
      go)  [ -x "$TOOLS_DIR/go/bin/$tool" ] && already_installed=1 ;;
      *)   has "$tool"                        && already_installed=1 ;;
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

    printf "  ${YELLOW}[...]${NC}  %-18s installing via %s...\n" "$tool" "$method"

    local install_ok=1
    case "$method" in
      system)
        pkg_install "$value" 2>/dev/null | tail -3 || install_ok=0
        ;;
      go)
        # GOBIN is exported by setup_go(); set inline too as a safety net
        GOPROXY=https://proxy.golang.org,direct GONOSUMDB='*' \
          GOPATH="$TOOLS_DIR/go" GOBIN="$TOOLS_DIR/go/bin" \
          go install -v "$value" 2>&1 | tail -3 || install_ok=0
        ;;
      pip)
        "$RECON_VENV/bin/pip" install --quiet "$value" 2>/dev/null || install_ok=0
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

  # ── Summary ────────────────────────────────────────────────────────────────
  echo ""
  echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
  echo -e "${BOLD}${CYAN}│  Installation Summary                                    │${NC}"
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

  # ── PATH persistence hint ──────────────────────────────────────────────────
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
#  STEP 5 — POST-INSTALL VERIFICATION
# =============================================================================

verify_install() {
  echo ""
  echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════╗${NC}"
  printf "${BOLD}${MAGENTA}║  %-44s║${NC}\n" "Post-Install Verification"
  echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════╝${NC}"
  echo ""

  local pass=0
  local fail=0
  local fail_list=()

  printf "  ${BOLD}%-20s %-12s %s${NC}\n" "TOOL" "METHOD" "STATUS"
  printf "  %s\n" "────────────────────────────────────────────────────────"

  for dep in "${DEPS[@]}"; do
    local tool="${dep%%:*}"
    local remainder="${dep#*:}"
    local method="${remainder%%:*}"
    local found=0 tool_path=""
    case "$method" in
      go)
        if [ -x "$TOOLS_DIR/go/bin/$tool" ]; then
          found=1; tool_path="$TOOLS_DIR/go/bin/$tool"
        fi
        ;;
      *)
        if has "$tool"; then
          found=1; tool_path="$(command -v "$tool")"
        fi
        ;;
    esac
    if [ "$found" -eq 1 ]; then
      printf "  ${GREEN}[OK ]${NC}  %-18s %-12s %s\n" "$tool" "$method" "$tool_path"
      pass=$((pass + 1))
    else
      printf "  ${RED}[---]${NC}  %-18s %-12s not found\n" "$tool" "$method"
      fail_list+=("$tool")
      fail=$((fail + 1))
    fi
  done

  # Venv check
  echo ""
  if [ -d "$RECON_VENV" ] && [ -x "$RECON_VENV/bin/python3" ]; then
    local py_ver; py_ver=$("$RECON_VENV/bin/python3" --version 2>&1)
    ok "Python venv   : $RECON_VENV ($py_ver)"
  else
    warn "Python venv   : not found at $RECON_VENV"
    fail=$((fail + 1))
  fi

  echo ""
  echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
  echo -e "${BOLD}${CYAN}│  Verification Result                                     │${NC}"
  echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
  echo ""
  ok "Installed : $pass / $((pass + fail))"
  if [ "$fail" -gt 0 ]; then
    warn "Missing   : $fail — ${fail_list[*]}"
    warn "Re-run './install.sh' to retry failed tools."
    return 1
  else
    ok "All tools verified — Rec0n-Zer0 is ready."
  fi
}

# =============================================================================
#  CHECK-ONLY MODE (--check flag)
# =============================================================================

check_only() {
  echo ""
  echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
  echo -e "${BOLD}${CYAN}│  Rec0n-Zer0 — Tool Status Check  (read-only)            │${NC}"
  echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
  echo ""
  info "Tools directory : $TOOLS_DIR"
  echo ""

  # Add tools directories to PATH for detection
  local go_bin="$TOOLS_DIR/go/bin"
  [ -d "$RECON_VENV/bin" ] && export PATH="$RECON_VENV/bin:$PATH"
  [ -d "$go_bin" ]          && export PATH="$go_bin:$PATH"

  local pass=0 fail=0
  local fail_list=()

  # python3 / pip / venv
  has python3 \
    && ok "python3       : $(python3 --version 2>&1)" \
    || { warn "python3       : not found"; fail=$((fail+1)); fail_list+=("python3"); }

  has go \
    && ok "go            : $(go version 2>/dev/null)" \
    || { warn "go            : not found"; fail=$((fail+1)); fail_list+=("go"); }

  if [ -d "$RECON_VENV" ] && [ -x "$RECON_VENV/bin/python3" ]; then
    ok "Python venv   : $RECON_VENV"
  else
    warn "Python venv   : not found — run ./install.sh"
    fail=$((fail+1)); fail_list+=("venv")
  fi

  echo ""
  printf "  ${BOLD}%-20s %-12s %s${NC}\n" "TOOL" "METHOD" "STATUS"
  printf "  %s\n" "────────────────────────────────────────────────────────"

  for dep in "${DEPS[@]}"; do
    local tool="${dep%%:*}"
    local remainder="${dep#*:}"
    local method="${remainder%%:*}"
    local found=0 tool_path=""
    case "$method" in
      go)
        if [ -x "$TOOLS_DIR/go/bin/$tool" ]; then
          found=1; tool_path="$TOOLS_DIR/go/bin/$tool"
        fi
        ;;
      *)
        if has "$tool"; then
          found=1; tool_path="$(command -v "$tool")"
        fi
        ;;
    esac
    if [ "$found" -eq 1 ]; then
      printf "  ${GREEN}[OK ]${NC}  %-18s %-12s %s\n" "$tool" "$method" "$tool_path"
      pass=$((pass + 1))
    else
      printf "  ${RED}[---]${NC}  %-18s %-12s not found\n" "$tool" "$method"
      fail_list+=("$tool")
      fail=$((fail + 1))
    fi
  done

  echo ""
  ok "Installed : $pass / $((pass + fail))"
  if [ "$fail" -gt 0 ]; then
    warn "Missing   : $fail — ${fail_list[*]}"
    echo ""
    info "Run './install.sh' to install all missing tools."
    return 1
  else
    ok "All tools are installed and ready."
  fi
}

# =============================================================================
#  UNINSTALL MODE (--uninstall flag)
# =============================================================================

uninstall_tools() {
  echo ""
  echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
  echo -e "${BOLD}${CYAN}│  Rec0n-Zer0 — Uninstall                                 │${NC}"
  echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
  echo ""
  info "Tools directory : $TOOLS_DIR"
  echo ""
  warn "This will remove:"
  echo "  • $TOOLS_DIR  (Go binaries + Python venv)"
  echo ""
  warn "System packages (amass, nmap, ffuf, etc.) will NOT be removed"
  warn "unless you answer Y to the optional prompt below."
  echo ""
  read -rp "$(echo -e "${BOLD}Remove $TOOLS_DIR? [y/N]: ${NC}")" confirm
  case "$confirm" in
    [Yy]*)
      if [ -d "$TOOLS_DIR" ]; then
        rm -rf "$TOOLS_DIR"
        ok "Removed $TOOLS_DIR"
      else
        warn "$TOOLS_DIR does not exist — nothing to remove"
      fi
      ;;
    *)
      info "Skipped removing $TOOLS_DIR"
      ;;
  esac

  # Optional: remove system packages
  echo ""
  warn "System packages installed by install.sh:"
  echo "  ${SYSTEM_PKGS[*]}"
  echo ""
  read -rp "$(echo -e "${BOLD}Remove system packages too? [y/N]: ${NC}")" rem_sys
  case "$rem_sys" in
    [Yy]*)
      detect_pkg_manager
      info "Removing system packages..."
      local resolved=()
      for pkg in "${SYSTEM_PKGS[@]}"; do
        resolved+=("$(_resolve_pkg "$pkg")")
      done
      case "$PKG_MGR" in
        apt) $SUDO apt-get remove -y "${resolved[@]}" 2>/dev/null || true
             $SUDO apt-get autoremove -y 2>/dev/null || true ;;
        dnf) $SUDO dnf remove -y "${resolved[@]}" 2>/dev/null || true ;;
        yum) $SUDO yum remove -y "${resolved[@]}" 2>/dev/null || true ;;
      esac
      ok "System packages removed."
      ;;
    *)
      info "System packages left in place."
      ;;
  esac

  echo ""
  ok "Uninstall complete. Run './install.sh' to reinstall."
}

# =============================================================================
#  HELP
# =============================================================================

usage() {
  echo -e "${BOLD}Usage:${NC}"
  echo "  ./install.sh [option]"
  echo ""
  echo -e "${BOLD}Options:${NC}"
  echo "  (none)         Full install — create Rec0n-Zer0-Tools/ and install all tools"
  echo "  -c, --check    Check tool status only — no changes made"
  echo "  -u, --uninstall  Remove Rec0n-Zer0-Tools/ (Go binaries + Python venv)"
  echo "  -h, --help     Show this help message"
  echo ""
  echo -e "${BOLD}Install location:${NC}"
  echo "  $TOOLS_DIR"
  echo ""
  echo -e "${BOLD}What gets installed:${NC}"
  echo "  Go tools   → $TOOLS_DIR/go/bin/"
  echo "  Pip tools  → $TOOLS_DIR/venv/bin/"
  echo "  System pkg → via apt (nmap, ffuf, gobuster, amass, etc.)"
  echo ""
  echo -e "${BOLD}Examples:${NC}"
  echo "  ./install.sh                # install everything"
  echo "  ./install.sh --check        # see what is/isn't installed"
  echo "  ./install.sh --uninstall    # remove Go/pip tools"
  echo ""
  echo -e "${BOLD}After install, add to ~/.zshrc to persist PATH:${NC}"
  echo "  export PATH=\"$TOOLS_DIR/go/bin:\$PATH\""
  echo "  export PATH=\"$TOOLS_DIR/venv/bin:\$PATH\""
  echo ""
}

# =============================================================================
#  BANNER
# =============================================================================

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════════╗"
  echo "  ║         Rec0n-Zer0 — Dependency Installer               ║"
  echo "  ╚══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "${DIM}  All Go/pip tools install into: ${CYAN}$TOOLS_DIR${NC}"
  echo -e "${DIM}  For authorized security engagements only.${NC}"
  echo ""
}

# =============================================================================
#  ENTRY POINT
# =============================================================================

main() {
  banner

  # ── Help mode ─────────────────────────────────────────────────────────────────
  if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
  fi

  # ── Uninstall mode ────────────────────────────────────────────────────────────
  if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "-u" ]; then
    uninstall_tools
    exit $?
  fi

  # ── Check-only mode ──────────────────────────────────────────────────────────
  if [ "${1:-}" = "--check" ] || [ "${1:-}" = "-c" ]; then
    check_only
    exit $?
  fi

  # ── Unknown flag ──────────────────────────────────────────────────────────────
  if [ -n "${1:-}" ]; then
    err "Unknown option: $1"
    echo ""
    usage
    exit 1
  fi

  # ── Confirm intent before making system changes ───────────────────────────────
  echo -e "This script will:"
  echo -e "  1. Create ${CYAN}$TOOLS_DIR/${NC}"
  echo -e "  2. Create a Python3 virtual environment at ${CYAN}$RECON_VENV${NC}"
  echo -e "  3. Install pip tools (dnsrecon, wafw00f) into the venv"
  echo -e "  4. Install Go tools into ${CYAN}$TOOLS_DIR/go/bin${NC}"
  echo -e "  5. Install system packages (nmap, ffuf, gobuster, etc.) via apt"
  echo ""
  read -rp "$(echo -e "${BOLD}Proceed? [y/N]: ${NC}")" confirm
  case "$confirm" in
    [Yy]*) ;;
    *) info "Aborted."; exit 0 ;;
  esac

  echo ""
  detect_pkg_manager
  check_disk_space

  # Update apt package index once
  if [ "$PKG_MGR" = "apt" ]; then
    info "Updating apt package index..."
    $SUDO apt-get update -qq 2>/dev/null || true
  fi

  setup_venv
  setup_go
  install_all_tools
  verify_install

  echo ""
  ok "Done! Start Rec0n-Zer0 with:  ./Rec0n-Zer0.sh"
  echo ""
}

main "$@"
