# Rec0n-Zer0.sh

Automated penetration testing reconnaissance suite for authorized security engagements. It automates the boring stuff so you can focus on what matters.

> **For authorized use only.** Only run against targets you have explicit permission to test.

---

## Credits

- [ProjectDiscovery](https://projectdiscovery.io) (subfinder, dnsx, naabu, httpx, katana, nuclei, and more)
- [Claude Code](https://claude.ai/claude-code) (Anthropic) — AI pair-programmer that wrote and refined this suite
- The open-source tool authors who make this suite possible

## Features

- Subdomain enumeration (subfinder, amass, assetfinder, findomain)
- DNS enumeration and zone transfer checks (dnsx, dnsrecon, dig, nmap)
- Port scanning (naabu, nmap, masscan)
- HTTP probing and WAF detection (httpx, wafw00f)
- Content/directory discovery (feroxbuster)
- URL discovery and web crawling (waybackurls, gau, katana, gospider, gf)
- Vulnerability scanning (nuclei, nikto)
- Secret and credential scanning (trufflehog, gitleaks)
- Screenshots (gowitness)
- Interactive menu with per-tool toggles, profiles, wordlist selector, and API key manager

---

## Requirements

- **Kali Linux** (designed and tested on Kali)
- Bash 4.0+
- Go (installed automatically via `apt` if missing)
- Python 3 + venv module (installed automatically if missing)
- ~2 GB free disk space for Go compilation

---

## Installation

All Go binaries and the Python virtual environment are installed into a `Rec0n-Zer0-Tools/` folder **next to the script** — nothing is written to your home directory or system paths.

### Quick Start

```bash
# Install dependencies
./install.sh

# Verify everything is installed
./install.sh --check

# Run recon
./Rec0n-Zer0.sh -d example.com
```

```bash
# Full install — creates Rec0n-Zer0-Tools/ in the same directory as the script
./install.sh

# Check what is already installed (read-only, no changes)
./install.sh --check

# Remove all installed Go/pip tools
./install.sh --uninstall
```

### What `install.sh` does

1. Creates `Rec0n-Zer0-Tools/` next to the script
2. Sets up a Python 3 virtual environment at `Rec0n-Zer0-Tools/venv/`
3. Installs pip tools (`dnsrecon`, `wafw00f`) into the venv
4. Installs Go tools into `Rec0n-Zer0-Tools/go/bin/`
5. Installs system packages (`nmap`, `feroxbuster`, etc.) via `apt`

> **System-installed tools:** `trufflehog` and `gitleaks` are installed via `apt` (not built from Go source).

| Package type | Install location |
|---|---|
| Go tools | `Rec0n-Zer0-Tools/go/bin/` |
| Python (pip) tools | `Rec0n-Zer0-Tools/venv/bin/` |
| System packages | system-wide via `apt` |

### Make PATH changes permanent

At the end of install, the exact `export` lines are printed. Add them to `~/.zshrc` (or `~/.bashrc`):

```bash
export PATH="/path/to/Rec0n-Zer0-Tools/go/bin:$PATH"
export PATH="/path/to/Rec0n-Zer0-Tools/venv/bin:$PATH"
```

> **Note:** `Rec0n-Zer0.sh` adds both paths to `PATH` automatically on every run, so this is only needed if you want to use the tools directly from your shell.

### Uninstall

```bash
./install.sh --uninstall
```

Removes `Rec0n-Zer0-Tools/` (Go binaries + Python venv). Optionally removes system packages installed by `apt` as well — the script prompts for each.

---

> **Disk space:** Go tool compilation (`naabu`, `nuclei`, `trufflehog`) requires ~2 GB of free space. The disk check is run against the partition where the script lives. If builds fail with "no space left on device", free space and re-run. You can reclaim the Go build cache with `go clean -cache`.

> **VM / VPN DNS note:** If `proxy.golang.org` is unreachable, `install.sh` automatically adds `nameserver 8.8.8.8` to `/etc/resolv.conf` as a fallback. This fixes Go module downloads on networks where the local DNS doesn't resolve external hostnames reliably.

> **Some tools** (`feroxbuster`, `findomain`) are not in standard Debian repos but are available on Kali Linux. If the `system` install fails for a tool, it will be listed in the summary — install it manually or ensure you are running Kali.

---

## Usage

> **Legal / Scope:** Use only on targets you own or have explicit, written permission to test. You are responsible for staying within the agreed scope and applicable laws.

```
./Rec0n-Zer0.sh [options] [domain]
```

### Options

| Flag | Description |
|------|-------------|
| `-d <domain>` | Target domain for recon (e.g. `example.com`) |
| `-i <file>` | IP/FQDN list for port scan — one address or hostname per line |
| `-e` | Check if all dependencies are installed (read-only status report) |
| `-h` | Show help |

### Modes

| Mode | Command |
|------|---------|
| Domain recon only | `./Rec0n-Zer0.sh -d example.com` |
| IP list scan only | `./Rec0n-Zer0.sh -i targets.txt` |
| **Combined** (domain recon → IP scan) | `./Rec0n-Zer0.sh -d example.com -i targets.txt` |
| Prompt for domain | `./Rec0n-Zer0.sh` |

### Combined mode

When both `-d` and `-i` are supplied the tool runs in **combined mode**:

1. Full interactive domain recon launches first (subdomain enum, DNS, ports, HTTP, fuzzing, vuln scan, etc.)
2. When you exit the menu by pressing **`0`**, the IP list scan starts automatically — no second invocation needed.

The IP file is validated before domain recon begins, so you get any path errors upfront.

---

## Examples

```bash
# Install all required tools
./install.sh

# Check tool status without installing anything
./install.sh --check

# Remove all installed tools
./install.sh --uninstall

# Interactive domain recon (prompts for domain)
./Rec0n-Zer0.sh

# Domain recon via flag (skips prompt)
./Rec0n-Zer0.sh -d example.com

# IP list port scan only
./Rec0n-Zer0.sh -i targets.txt

# Combined: domain recon then IP scan
./Rec0n-Zer0.sh -d example.com -i targets.txt

# Check if all required tools are installed
./Rec0n-Zer0.sh -e
```

---

## Run Profiles

Select a profile at startup or press **`P`** in the menu:

| Profile | Description |
|---------|-------------|
| Quick | Fast essentials only (~10–20 min) |
| Standard | Balanced coverage (default) |
| Comprehensive | All tools enabled |

Profiles can be overridden per-tool from the **`T`** menu.

---

## Interactive Menu

```
── Run Modes ──────────────────────────────────
 A  Quick Recon       (fast profile, all modules)
 B  Full Recon        (current profile, all modules)
 C  Custom Recon      (pick which modules to run)
 I  IP List Scan      (nmap against a file of IPs/FQDNs)

── Individual Modules ─────────────────────────
 1  Subdomain Enumeration
 2  DNS Enumeration
 3  Port Scanning
 4  HTTP Probing & Tech Detection
 5  Content Discovery  (dir fuzzing)
 6  URL Discovery      (archives + crawling)
 7  Vulnerability Scanning  (nuclei)
 8  Screenshots
 9  Subdomain Takeover Check
10  JS Secret Scanning

── Configuration ──────────────────────────────
 P  Set Profile        (Quick / Standard / Comprehensive)
 T  Configure Tools    (toggle individual tools on/off)
 W  Set Wordlist       (for feroxbuster)
 K  API Keys           (subfinder/findomain/gau)
 D  Install Dependencies  (go/pip3 auto-install)
 G  Generate Summary
 X  Change Target
 0  Exit
```

---

## Directory Structure

After install, the project directory looks like:

```
Claude-Projects/               ← wherever the script lives
├── Rec0n-Zer0.sh
├── install.sh
├── README.md
└── Rec0n-Zer0-Tools/          ← created by install.sh
    ├── go/
    │   └── bin/               ← subfinder, dnsx, naabu, httpx, katana, nuclei, ...
    └── venv/
        └── bin/               ← dnsrecon, wafw00f
```

Scan results are saved next to the script as well:

```
example.com_recon_20260219_1400/
├── subdomains/
├── dns/
├── ports/
├── http/
├── content/
├── urls/
├── vulns/
├── screenshots/
├── takeover/
└── recon.log
```

---

## Environment Overrides

```bash
WORDLIST=/path/to/list.txt ./Rec0n-Zer0.sh -d example.com   # custom wordlist
ENABLE_AMASS=0 ./Rec0n-Zer0.sh -d example.com               # disable a tool
API_SHODAN=abc123 ./Rec0n-Zer0.sh -d example.com            # inline API key
TOOL_TIMEOUT=600 ./Rec0n-Zer0.sh -d example.com             # increase per-tool timeout
THREADS=100 ./Rec0n-Zer0.sh -d example.com                  # increase concurrency
```

---

## API Keys

Keys are optional — all tools function without them, but keys increase coverage.

Configure interactively by pressing **`K`** in the menu, or set inline via environment variables.

Saved to `~/.config/recon/api_keys.conf` (chmod 600).

| Key | Used by |
|-----|---------|
| Shodan | subfinder, findomain |
| GitHub token | subfinder |
| VirusTotal | subfinder, findomain |
| SecurityTrails | subfinder |
| Censys ID + Secret | subfinder |
| AlienVault OTX | gau |
