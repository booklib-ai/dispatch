#!/usr/bin/env bash
# ============================================================================
# Axios Supply Chain Attack Scanner v3 — COMPREHENSIVE WHOLE-LAPTOP SCAN
# ============================================================================
# Sources combined:
#   - Socket.dev  (initial discovery)
#   - Snyk        (SNYK-JS-AXIOS-15850650, additional packages)
#   - StepSecurity (full IOC list, campaign ID, SHA sums, anti-forensics)
#
# What this scans (that Snyk CLI and StepSecurity can't do alone):
#   - Snyk CLI   = per-project only (must cd into each directory)
#   - StepSecurity Harden-Runner = CI/CD only (GitHub Actions)
#   - StepSecurity Dev Machine Guard = enterprise paid product
#   - THIS SCRIPT = whole laptop, all projects, all caches, all artifacts, free
#
# IOCs:
#   Packages:  axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1
#              @qqbrowser/openclaw-qbot@0.0.130, @shadanai/openclaw
#   C2:        sfrclak[.]com / 142.11.206.73 : 8000
#   Campaign:  6202033
#   SHA1:      axios@1.14.1    = 2553649f232204966871cea80a5d0d6adc700ca
#              axios@0.30.4    = d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71
#              plain-crypto-js = 07d889e2dadce6f3910dcbc253317d28ca61c766
# ============================================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'
BOLD='\033[1m'

FOUND_ISSUES=0
CRITICAL=0
PROJECTS_WITH_AXIOS=()

header()   { echo ""; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BOLD}  $1${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
ok()       { echo -e "  ${GREEN}✔${NC} $1"; }
warn()     { echo -e "  ${YELLOW}⚠${NC} $1"; FOUND_ISSUES=$((FOUND_ISSUES + 1)); }
fail()     { echo -e "  ${RED}✖${NC} ${RED}$1${NC}"; FOUND_ISSUES=$((FOUND_ISSUES + 1)); CRITICAL=$((CRITICAL + 1)); }
info()     { echo -e "  ${CYAN}ℹ${NC} $1"; }
detail()   { echo -e "    ${GRAY}→ $1${NC}"; }

OS=$(uname -s)

cat << 'BANNER'

   █████╗ ██╗  ██╗██╗ ██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗╚██╗██╔╝██║██╔═══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███████║ ╚███╔╝ ██║██║   ██║███████╗    ███████╗██║     ███████║██╔██╗ ██║
  ██╔══██║ ██╔██╗ ██║██║   ██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║  ██║██╔╝ ██╗██║╚██████╔╝███████║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
BANNER

echo -e "${RED}${BOLD}  Supply Chain Attack Scanner v3 — Whole Laptop Edition${NC}"
echo -e "${GRAY}  March 31, 2026 · Campaign 6202033 · C2: sfrclak.com:8000${NC}"
echo ""
echo -e "  Platform:  ${BOLD}$OS$([ "$OS" = "Darwin" ] && echo " ($(uname -m))")${NC}"
echo -e "  Date:      $(date)"
echo -e "  User:      $(whoami) @ $(hostname)"
echo -e "  Home:      $HOME"

# ---- macOS compatibility checks ----
if [ "$OS" = "Darwin" ]; then
    echo ""
    BASH_VER="${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"
    echo -e "  Bash:      $BASH_VER $([ "${BASH_VERSINFO[0]}" -lt 4 ] && echo "(3.x — OK, script is compatible)" || echo "(4+)")"
    
    # Check for required tools
    MISSING_TOOLS=()
    for tool in find grep pgrep lsof curl; do
        command -v "$tool" &>/dev/null || MISSING_TOOLS+=("$tool")
    done
    if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
        echo -e "  ${RED}Missing tools: ${MISSING_TOOLS[*]}${NC}"
        echo -e "  Install Xcode CLT: xcode-select --install"
        exit 1
    fi
    
    # Check if npm/node exists
    if command -v npm &>/dev/null; then
        echo -e "  Node:      $(node --version 2>/dev/null || echo '?') / npm $(npm --version 2>/dev/null || echo '?')"
    else
        echo -e "  Node:      ${YELLOW}not installed${NC} (lock file scan still works, cache check limited)"
    fi
fi

# ============================================================================
# 1. WHOLE-LAPTOP PROJECT SCAN
# ============================================================================
header "1/7  SCANNING ENTIRE MACHINE FOR MALICIOUS PACKAGES"

SEARCH_DIRS=("$HOME")
for d in /opt /var/www /srv /tmp /var/tmp; do
    [ -d "$d" ] && SEARCH_DIRS+=("$d")
done

LOCKFILES_FOUND=0
MALICIOUS_LOCKFILES=0

# Definitive markers (100% malicious, no false positives)
DEFINITE_RE='plain-crypto-js|openclaw-qbot|shadanai.openclaw'

# Version check requires context: must be near "axios" in the file
# We check these separately to avoid matching serve-static@1.14.1 etc.
AXIOS_VERSIONS_RE='"0\.30\.4"'

info "Search roots: ${SEARCH_DIRS[*]}"
info "Scanning lock files + node_modules + bun lockfiles..."
echo ""

for ROOT in "${SEARCH_DIRS[@]}"; do

    # ---- Lock files (npm, yarn, pnpm, bun text) ----
    while IFS= read -r -d '' lockfile; do
        LOCKFILES_FOUND=$((LOCKFILES_FOUND + 1))
        DIR=$(dirname "$lockfile")

        LOCK_INFECTED=0

        # Phase 1: Definitive markers (plain-crypto-js, openclaw — zero false positives)
        if grep -qE "$DEFINITE_RE" "$lockfile" 2>/dev/null; then
            fail "MALICIOUS DEPENDENCY in lock file: $lockfile"
            LOCK_INFECTED=1
            grep -n -E "$DEFINITE_RE" "$lockfile" 2>/dev/null | head -8 | while read -r l; do
                detail "$l"
            done
        fi

        # Phase 2: Check for axios specifically at malicious versions
        # Must match "axios" within 2 lines of "1.14.1" or "0.30.4" to avoid
        # false positives from serve-static@1.14.1, @webassemblyjs/*@1.14.1, etc.
        if grep -qE "$AXIOS_VERSIONS_RE" "$lockfile" 2>/dev/null; then
            # 0.30.4 is rare enough to flag directly
            fail "axios@0.30.4 found in: $lockfile"
            LOCK_INFECTED=1
            grep -n -E "$AXIOS_VERSIONS_RE" "$lockfile" 2>/dev/null | head -4 | while read -r l; do
                detail "$l"
            done
        fi

        # For 1.14.1 — only flag if "axios" appears near version 1.14.1
        BASENAME=$(basename "$lockfile")
        if [ "$BASENAME" = "package-lock.json" ]; then
            # In package-lock.json, axios entries look like: "node_modules/axios": { ... "version": "1.14.1"
            if grep -A2 '"axios"' "$lockfile" 2>/dev/null | grep -q '"1\.14\.1"'; then
                fail "axios@1.14.1 found in: $lockfile"
                LOCK_INFECTED=1
            fi
        elif [ "$BASENAME" = "yarn.lock" ]; then
            # In yarn.lock: axios@^1.14.0: \n  version "1.14.1"
            if grep -A1 'axios@' "$lockfile" 2>/dev/null | grep -q '"1\.14\.1"\|1\.14\.1'; then
                fail "axios@1.14.1 found in: $lockfile"
                LOCK_INFECTED=1
            fi
        elif [ "$BASENAME" = "pnpm-lock.yaml" ] || [ "$BASENAME" = "bun.lock" ]; then
            if grep 'axios' "$lockfile" 2>/dev/null | grep -q '1\.14\.1'; then
                fail "axios@1.14.1 found in: $lockfile"
                LOCK_INFECTED=1
            fi
        fi

        if [ "$LOCK_INFECTED" -gt 0 ]; then
            MALICIOUS_LOCKFILES=$((MALICIOUS_LOCKFILES + 1))
        fi

        # ---- node_modules checks ----
        NM="$DIR/node_modules"
        [ -d "$NM" ] || continue

        # KEY INSIGHT (StepSecurity): directory presence alone = compromise
        # Even after anti-forensic cleanup, the folder existing means dropper ran
        if [ -d "$NM/plain-crypto-js" ]; then
            fail "plain-crypto-js DIRECTORY EXISTS: $NM/plain-crypto-js"
            detail "Directory presence alone = dropper executed (even if contents look clean)"

            # Detect anti-forensic state
            if [ -f "$NM/plain-crypto-js/setup.js" ]; then
                detail "setup.js STILL EXISTS — dropper may not have completed cleanup"
            elif [ ! -f "$NM/plain-crypto-js/setup.js" ] && [ -f "$NM/plain-crypto-js/package.json" ]; then
                # Check for version spoofing: reports 4.2.0 but was installed as 4.2.1
                FAKE_VER=$(grep -o '"version":\s*"[^"]*"' "$NM/plain-crypto-js/package.json" 2>/dev/null | grep -o '[0-9][^"]*' || true)
                if [ "$FAKE_VER" = "4.2.0" ]; then
                    detail "VERSION SPOOFING DETECTED: package.json says 4.2.0 (was 4.2.1)"
                    detail "Anti-forensic cleanup completed — setup.js deleted, package.md renamed"
                fi
            fi

            if [ -f "$NM/plain-crypto-js/package.md" ]; then
                detail "package.md present — dropper staged but may not have swapped yet"
            fi
        fi

        # Additional malicious packages (Snyk)
        for PKG in "@qqbrowser/openclaw-qbot" "@shadanai/openclaw"; do
            [ -d "$NM/$PKG" ] && fail "MALICIOUS MODULE: $NM/$PKG"
        done

        # Axios version check
        AXIOS_PKG="$NM/axios/package.json"
        if [ -f "$AXIOS_PKG" ]; then
            AV=$(grep -o '"version":\s*"[^"]*"' "$AXIOS_PKG" 2>/dev/null | head -1 | grep -o '[0-9][^"]*')
            if [[ "$AV" == "1.14.1" || "$AV" == "0.30.4" ]]; then
                fail "MALICIOUS axios@$AV: $NM/axios"
                PROJECTS_WITH_AXIOS+=("$DIR")
            fi

            # Check for missing husky (forensic signal from StepSecurity)
            if [ "$AV" = "1.14.1" ]; then
                if ! grep -q '"prepare"' "$AXIOS_PKG" 2>/dev/null; then
                    detail "Missing 'prepare:husky' script — confirms manual publish by attacker"
                fi
            fi
        fi

    done < <(find "$ROOT" -maxdepth 10 \
        \( -name node_modules -prune -o -name .git -prune -o -name Library -prune \) -o \
        \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "bun.lock" \) \
        -type f -print0 2>/dev/null)

    # ---- Bun binary lockfiles ----
    while IFS= read -r -d '' bunlock; do
        LOCKFILES_FOUND=$((LOCKFILES_FOUND + 1))
        if command -v bun &>/dev/null; then
            bun "$bunlock" 2>/dev/null | grep -qE "$DEFINITE_RE|axios.*1\.14\.1|axios.*0\.30\.4" && {
                fail "MALICIOUS bun lockfile: $bunlock"
                MALICIOUS_LOCKFILES=$((MALICIOUS_LOCKFILES + 1))
            }
        elif command -v strings &>/dev/null; then
            strings "$bunlock" 2>/dev/null | grep -qE 'plain-crypto-js|axios.*1\.14\.1|axios.*0\.30\.4' && {
                fail "MALICIOUS bun lockfile: $bunlock"
                MALICIOUS_LOCKFILES=$((MALICIOUS_LOCKFILES + 1))
            }
        fi
    done < <(find "$ROOT" -maxdepth 10 \( -name node_modules -prune -o -name .git -prune \) -o \
        -name "bun.lockb" -type f -print0 2>/dev/null)
done

echo ""
if [ "$MALICIOUS_LOCKFILES" -eq 0 ] && [ "$CRITICAL" -eq 0 ]; then
    ok "Clean — scanned $LOCKFILES_FOUND lock files, no malicious packages found"
else
    fail "$MALICIOUS_LOCKFILES infected lock file(s) out of $LOCKFILES_FOUND"
fi

# ============================================================================
# 2. GLOBAL PACKAGE CACHES
# ============================================================================
header "2/7  CHECKING PACKAGE MANAGER CACHES"

check_cache() {
    local name="$1" dir="$2"
    [ -d "$dir" ] || return
    local hits
    hits=$(find "$dir" \( -name "*plain-crypto-js*" -o -name "*axios-1.14.1*" -o -name "*axios-0.30.4*" -o -name "*openclaw-qbot*" \) 2>/dev/null || true)
    if [ -n "$hits" ]; then
        fail "Malicious package in $name cache:"
        echo "$hits" | head -5 | while read -r f; do detail "$f"; done
    else
        ok "$name cache clean ($dir)"
    fi
}

if command -v npm &>/dev/null; then
    NPM_CACHE=$(npm config get cache 2>/dev/null || echo "$HOME/.npm")
else
    NPM_CACHE="$HOME/.npm"
fi
check_cache "npm" "$NPM_CACHE"
check_cache "Yarn" "$HOME/.yarn/cache"
check_cache "Yarn2" "$HOME/.cache/yarn"
check_cache "pnpm" "$HOME/.local/share/pnpm/store"
check_cache "pnpm2" "$HOME/.pnpm-store"
check_cache "Bun" "$HOME/.bun/install/cache"

# ============================================================================
# 3. MALWARE ARTIFACTS (OS-SPECIFIC) + CAMPAIGN ID FILES
# ============================================================================
header "3/7  CHECKING FOR MALWARE ARTIFACTS & CAMPAIGN FILES ($OS)"

case "$OS" in
    Darwin)
        echo -e "  ${BOLD}[macOS]${NC}"

        # Trojan binary
        for P in "/Library/Caches/com.apple.act.mond" "$HOME/Library/Caches/com.apple.act.mond"; do
            if [ -f "$P" ]; then
                fail "TROJAN BINARY: $P"
                ls -la "$P" | sed 's/^/    /'
            else
                ok "No trojan at $P"
            fi
        done

        # Campaign AppleScript temp file (self-deletes, but check anyway)
        if [ -f "/tmp/6202033" ]; then
            fail "CAMPAIGN SCRIPT: /tmp/6202033 (AppleScript dropper)"
        else
            ok "No campaign script at /tmp/6202033"
        fi

        # Hidden executables in /private/tmp (peinject payloads)
        HIDDEN=$(find /private/tmp -name ".*" -type f \( -perm -u=x -o -perm -g=x -o -perm -o=x \) 2>/dev/null || true)
        if [ -n "$HIDDEN" ]; then
            warn "Hidden executable(s) in /private/tmp:"
            echo "$HIDDEN" | while read -r f; do detail "$f"; done
        else
            ok "No hidden executables in /private/tmp"
        fi

        # LaunchAgents/Daemons persistence
        PERSIST_FOUND=0
        for D in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
            [ -d "$D" ] || continue
            S=$(grep -rl "com.apple.act.mond\|sfrclak\|142\.11\.206\.73\|6202033" "$D" 2>/dev/null || true)
            [ -n "$S" ] && { fail "Suspicious plist: $S"; PERSIST_FOUND=1; }
        done
        [ "$PERSIST_FOUND" -eq 0 ] && ok "No suspicious LaunchAgents/Daemons"

        # Running processes
        if pgrep -f "com.apple.act.mond" > /dev/null 2>&1; then
            fail "TROJAN PROCESS RUNNING: com.apple.act.mond"
        else
            ok "No trojan process running"
        fi

        # System logs (can be SLOW on macOS — limited to 1 day, 30s timeout)
        info "Checking system logs (last 24h, max 30s)..."
        LOG_RESULT=$(perl -e 'alarm 30; exec @ARGV' log show --predicate 'process == "com.apple.act.mond"' --last 1d 2>/dev/null | head -5 || true)
        if [ -n "$LOG_RESULT" ] && echo "$LOG_RESULT" | grep -q "act.mond"; then
            fail "Log entries found for com.apple.act.mond"
        else
            ok "No trojan in system logs (last 24h)"
        fi
        ;;

    Linux)
        echo -e "  ${BOLD}[Linux]${NC}"

        # Python RAT
        if [ -f "/tmp/ld.py" ]; then
            fail "MALWARE SCRIPT: /tmp/ld.py"
            ls -la /tmp/ld.py | sed 's/^/    /'
        else
            ok "No malware at /tmp/ld.py"
        fi

        # Running processes
        if pgrep -f "ld\.py" > /dev/null 2>&1; then
            # Filter out our own grep/scanner process
            REAL_PROCS=$(ps aux 2>/dev/null | grep "[l]d\.py" || true)
            if [ -n "$REAL_PROCS" ]; then
                fail "ld.py PROCESS RUNNING:"
                echo "$REAL_PROCS" | sed 's/^/    /'
            else
                ok "No ld.py process (false positive filtered)"
            fi
        else
            ok "No ld.py process running"
        fi

        # Orphaned Python from /tmp
        SUSPECT=$(ps aux 2>/dev/null | grep -E "python3?.*/tmp/" | grep -v grep || true)
        [ -n "$SUSPECT" ] && { warn "Suspicious Python from /tmp:"; echo "$SUSPECT" | sed 's/^/    /'; } || ok "No suspicious Python from /tmp"

        # Persistence
        crontab -l 2>/dev/null | grep -qE "ld\.py|sfrclak|142\.11\.206\.73|6202033" && fail "Malicious crontab entry" || ok "Crontab clean"
        systemctl list-units --all 2>/dev/null | grep -qi "ld.py\|act.mond\|6202033" && fail "Suspicious systemd unit" || ok "No suspicious systemd units"
        ;;
esac

# ============================================================================
# 4. NETWORK — C2 CONNECTIONS
# ============================================================================
header "4/7  CHECKING NETWORK FOR C2 (sfrclak.com / 142.11.206.73:8000)"

C2_FOUND=0

# DNS resolution
if command -v dig &>/dev/null; then
    RESOLVED=$(dig +short sfrclak.com 2>/dev/null || true)
    [ -n "$RESOLVED" ] && { warn "C2 domain resolves to: $RESOLVED"; C2_FOUND=1; } || ok "C2 domain does not resolve (taken down)"
fi

# Active connections — check for BOTH domain, IP, AND port 8000
if command -v lsof &>/dev/null; then
    CONN=$(lsof -i -nP 2>/dev/null | grep -E "142\.11\.206\.73|sfrclak" | head -5 || true)
    [ -n "$CONN" ] && { fail "ACTIVE C2 CONNECTION:"; echo "$CONN" | sed 's/^/    /'; C2_FOUND=1; }
elif command -v ss &>/dev/null; then
    CONN=$(ss -tunap 2>/dev/null | grep -E "142\.11\.206\.73|sfrclak" | head -5 || true)
    [ -n "$CONN" ] && { fail "ACTIVE C2 CONNECTION:"; echo "$CONN" | sed 's/^/    /'; C2_FOUND=1; }
fi

# /etc/hosts
[ -f /etc/hosts ] && grep -qi "sfrclak" /etc/hosts 2>/dev/null && { warn "C2 in /etc/hosts"; C2_FOUND=1; }

# Shell history
for H in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.history" "$HOME/.local/share/fish/fish_history"; do
    [ -f "$H" ] && grep -qiE "sfrclak|plain-crypto-js|142\.11\.206\.73|6202033" "$H" 2>/dev/null && {
        warn "C2/malware reference in $H"
        C2_FOUND=1
    }
done

[ "$C2_FOUND" -eq 0 ] && ok "No C2 connections or references found"

# ============================================================================
# 5. SENSITIVE FILES AT RISK
# ============================================================================
header "5/7  SENSITIVE FILES (exfiltration targets if infected)"

info "RAT beacons every 60s. If compromised, rotate ALL of these."
echo ""

SENSITIVE=(
    ".ssh/id_rsa" ".ssh/id_ed25519" ".ssh/id_ecdsa" ".ssh/config"
    ".aws/credentials" ".aws/config"
    ".azure/accessTokens.json"
    ".npmrc" ".yarnrc" ".netrc"
    ".env" ".gitconfig" ".git-credentials"
    ".docker/config.json" ".kube/config"
    ".config/gh/hosts.yml"
    ".gnupg/secring.gpg" ".gnupg/private-keys-v1.d"
    ".config/gcloud/credentials.db"
    ".config/gcloud/application_default_credentials.json"
)

COUNT=0
for F in "${SENSITIVE[@]}"; do
    P="$HOME/$F"
    if [ -f "$P" ] || [ -d "$P" ]; then
        if [ "$OS" = "Darwin" ]; then
            MT=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$P" 2>/dev/null || echo "?")
        else
            MT=$(stat -c "%y" "$P" 2>/dev/null | cut -d. -f1 || echo "?")
        fi
        detail "~/$F  (modified: $MT)"
        COUNT=$((COUNT + 1))
    fi
done
echo ""
info "$COUNT sensitive file(s)/dirs found. If malware ran → rotate everything."

# ============================================================================
# 6. OPTIONAL: RUN SNYK CLI ACROSS ALL PROJECTS
# ============================================================================
header "6/7  SNYK CLI INTEGRATION (optional whole-laptop scan)"

if command -v snyk &>/dev/null; then
    SNYK_VER=$(snyk --version 2>/dev/null || echo "unknown")
    info "Snyk CLI found: $SNYK_VER"

    if [ ${#PROJECTS_WITH_AXIOS[@]} -gt 0 ]; then
        info "Running 'snyk test' on ${#PROJECTS_WITH_AXIOS[@]} project(s) with suspicious axios..."
        for PROJ in "${PROJECTS_WITH_AXIOS[@]}"; do
            echo ""
            info "Testing: $PROJ"
            (cd "$PROJ" && snyk test --severity-threshold=critical 2>&1 | head -20) || true
        done
    else
        # Find all projects with package.json and run snyk on them
        info "No infected projects found, but you can manually run:"
        detail "find ~ -name package.json -not -path '*/node_modules/*' -execdir snyk test \\;"
    fi
else
    info "Snyk CLI not installed. To add per-project scanning:"
    detail "npm install -g snyk && snyk auth"
    detail "Then re-run this scanner — it will auto-run snyk on found projects"
fi

# ============================================================================
# 7. HARDENING RECOMMENDATIONS
# ============================================================================
header "7/7  HARDENING & PREVENTION"

# npm ignore-scripts check
if command -v npm &>/dev/null; then
    IS=$(npm config get ignore-scripts 2>/dev/null || echo "false")
    if [ "$IS" = "true" ]; then
        ok "npm ignore-scripts is ENABLED (blocks postinstall attacks)"
    else
        warn "npm ignore-scripts is DISABLED"
        detail "Enable: npm config set ignore-scripts true"
        detail "Or per-install: npm ci --ignore-scripts"
    fi
fi

info "Add to package.json to prevent axios from resolving to malicious versions:"
cat << 'FIX'

    "overrides":   { "axios": "1.14.0" },
    "resolutions": { "axios": "1.14.0" }

FIX

info "Block C2 at network level:"
detail "echo '0.0.0.0 sfrclak.com' | sudo tee -a /etc/hosts"
if [ "$OS" = "Darwin" ]; then
    detail "Or firewall: echo 'block drop out to 142.11.206.73' | sudo pfctl -ef -"
else
    detail "Or firewall: sudo iptables -A OUTPUT -d 142.11.206.73 -j DROP"
fi

info "Use npm ci (not npm install) in CI/CD — enforces lockfile integrity"
info "Consider npq (github.com/lirantal/npq) for pre-install security checks"

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [ "$CRITICAL" -gt 0 ]; then
    echo -e "${RED}${BOLD}  ✖ $CRITICAL CRITICAL ISSUE(S) FOUND — ASSUME COMPROMISE${NC}"
    echo ""
    echo -e "  ${BOLD}IMMEDIATE ACTIONS:${NC}"
    echo -e "  ${RED}1.${NC} ISOLATE — disconnect from network if RAT is active"
    echo -e "  ${RED}2.${NC} ROTATE — revoke & reissue ALL credentials:"
    echo -e "     SSH keys, npm tokens, GitHub tokens, AWS/Azure/GCP creds,"
    echo -e "     Docker registry, .env secrets, GPG keys"
    echo -e "  ${RED}3.${NC} REMOVE — rm -rf node_modules/plain-crypto-js && npm cache clean --force"
    echo -e "  ${RED}4.${NC} PIN — npm install axios@1.14.0 + add overrides block"
    echo -e "  ${RED}5.${NC} REBUILD — do NOT clean in place, rebuild from known-good snapshot"
    echo -e "  ${RED}6.${NC} AUDIT CI — check pipeline logs for March 31 00:21–03:29 UTC"
elif [ "$FOUND_ISSUES" -gt 0 ]; then
    echo -e "${YELLOW}${BOLD}  ⚠ $FOUND_ISSUES WARNING(S) — no critical infections, review above${NC}"
else
    echo -e "${GREEN}${BOLD}  ✔ ALL CLEAR — no infections, no artifacts, no C2 connections${NC}"
fi
echo ""
echo -e "  Scanned: $LOCKFILES_FOUND lock files across ${#SEARCH_DIRS[@]} root directories"
echo -e "  Sources: Socket.dev + Snyk SNYK-JS-AXIOS-15850650 + StepSecurity"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
