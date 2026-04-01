# 🔴 Axios npm Supply Chain Attack — March 31, 2026

**Campaign ID:** 6202033  
**C2:** sfrclak[.]com / 142.11.206.73:8000  
**Affected:** axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1  
**Window:** March 31, 00:21–03:29 UTC (~3 hours)  
**Status:** Resolved — malicious versions removed from npm  

## TL;DR

A hijacked npm maintainer account was used to publish poisoned axios versions (1.14.1 and 0.30.4) containing a hidden dependency (`plain-crypto-js@4.2.1`) that deploys a cross-platform RAT (Remote Access Trojan). The dropper contacts C2 at `sfrclak.com:8000`, installs platform-specific malware, then erases itself.

**Run the scanner:** `chmod +x scan.sh && ./scan.sh`

## Who is at risk

- CI/CD pipelines that ran `npm install` with unpinned axios (`^1.14.0`) between 00:21–03:29 UTC on March 31
- Developers who ran `npm install` or `npm update` in that 3-hour window
- Projects using `@qqbrowser/openclaw-qbot@0.0.130` or `@shadanai/openclaw` (no time window constraint)

**If your lockfile was committed before March 31 and you used `npm ci`, you were NOT affected.**

## Scanner Tool

The included `scan.sh` performs a **whole-laptop scan** (not per-project like `snyk test`):

| Check | What it does |
|-------|-------------|
| 1. Lock files | Scans all lock files recursively across your entire machine |
| 2. node_modules | Checks for `plain-crypto-js` directory (presence alone = compromise) |
| 3. Package caches | npm, Yarn, pnpm, Bun global caches |
| 4. Malware artifacts | OS-specific trojan files (macOS/Linux/Windows) |
| 5. C2 connections | Active connections to `sfrclak.com` / `142.11.206.73` |
| 6. Credential files | Lists sensitive files that may have been exfiltrated |
| 7. Hardening | Checks `ignore-scripts` config, recommends `overrides` block |

### Compatibility

- macOS (Catalina through Sequoia, Intel + Apple Silicon, Bash 3.2 compatible)
- Linux (Ubuntu, Debian, RHEL, etc.)
- Works with or without Node.js/npm installed

### Usage

```bash
chmod +x scan.sh
./scan.sh
```

## Indicators of Compromise

### Malicious Packages

| Package | SHA1 |
|---------|------|
| axios@1.14.1 | `2553649f232204966871cea80a5d0d6adc700ca` |
| axios@0.30.4 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js@4.2.1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

### File System IOCs

| Platform | Path | Description |
|----------|------|-------------|
| macOS | `/Library/Caches/com.apple.act.mond` | RAT binary (spoofs Apple daemon) |
| macOS | `/tmp/6202033` | AppleScript dropper (self-deletes) |
| macOS | `/private/tmp/.*` | Ad-hoc signed peinject payloads |
| Windows | `%PROGRAMDATA%\wt.exe` | PowerShell copy (persists across reboots) |
| Windows | `%TEMP%\6202033.vbs/.ps1` | Dropper scripts (self-delete) |
| Linux | `/tmp/ld.py` | Python RAT |

### Network IOCs

| Indicator | Value |
|-----------|-------|
| C2 domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| C2 port | `8000` |
| C2 URL | `http://sfrclak.com:8000/6202033` |

### Anti-Forensic Behavior

After execution the malware erases itself:
1. Deletes `setup.js` (the dropper)
2. Deletes `package.json` (containing the postinstall hook)
3. Renames `package.md` → `package.json` (clean stub reporting version **4.2.0**, not 4.2.1)

**Key insight:** After cleanup, `npm list` reports `plain-crypto-js@4.2.0` — not the malicious `4.2.1`. The **directory existence alone** is proof of compromise.

## If You Are Compromised

1. **Isolate** — disconnect from network
2. **Rotate everything** — SSH keys, npm tokens, GitHub tokens, AWS/Azure/GCP credentials, Docker registry, `.env` secrets
3. **Remove** — `rm -rf node_modules/plain-crypto-js && npm cache clean --force`
4. **Pin** — `npm install axios@1.14.0` + add `overrides`/`resolutions` block
5. **Rebuild** — do NOT clean in place, rebuild from known-good snapshot
6. **Audit CI** — check pipeline logs for March 31 00:21–03:29 UTC

## Sources

- [Socket.dev — Axios npm Package Compromised](https://socket.dev/blog/axios-npm-package-compromised)
- [Snyk — SNYK-JS-AXIOS-15850650](https://security.snyk.io/vuln/SNYK-JS-AXIOS-15850650)
- [StepSecurity — Full Technical Analysis](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [GitHub Issue — axios/axios#10604](https://github.com/axios/axios/issues/10604)

---

*Published by [booklib-ai](https://github.com/booklib-ai) · [dispatch](https://github.com/booklib-ai/dispatch)*
