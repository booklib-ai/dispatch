---
title: "I built a whole-laptop scanner for the Axios supply chain attack — here's what it checks"
published: false
description: "axios@1.14.1 was compromised with a RAT. Snyk scans per-project. Our open-source scanner checks your entire machine in one command."
tags: security, npm, javascript, opensource
cover_image: 
---

On March 31, 2026, attackers hijacked the npm maintainer account for **axios** (300M+ weekly downloads) and published poisoned versions that deploy a cross-platform Remote Access Trojan. The malicious versions were live for ~3 hours before being pulled.

Every security vendor published analysis. None shipped a tool that scans your **entire laptop**.

So we built one.

## The 30-second version

```bash
curl -sL https://raw.githubusercontent.com/booklib-ai/dispatch/main/dispatches/2026-04-01-axios-supply-chain-attack/scan.sh -o scan.sh
chmod +x scan.sh
./scan.sh
```

This scans every npm project on your machine, checks for malware artifacts, verifies no C2 connections are active, and lists credentials that may have been exfiltrated.

## What happened

The attacker compromised the `jasonsaayman` npm account and published:
- `axios@1.14.1` (targeting the 1.x user base)
- `axios@0.30.4` (targeting the legacy 0.x branch)

Both versions inject `plain-crypto-js@4.2.1` — a package that runs a `postinstall` script deploying platform-specific RATs:
- **macOS**: Binary at `/Library/Caches/com.apple.act.mond`
- **Windows**: PowerShell copy at `%PROGRAMDATA%\wt.exe`
- **Linux**: Python script at `/tmp/ld.py`

After execution, the malware **deletes itself** and replaces its `package.json` with a clean version. If you inspect `node_modules` after the fact, everything looks normal.

## Why existing tools aren't enough

| Tool | Limitation |
|------|-----------|
| `snyk test` | Per-project only — must `cd` into each directory |
| StepSecurity Harden-Runner | CI/CD only (GitHub Actions) |
| StepSecurity Dev Machine Guard | Enterprise paid product |
| `npm audit` | Doesn't check for malware artifacts on disk |

Our scanner does **7 checks across your entire machine**:

1. **All lock files** — recursively finds every `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`
2. **node_modules** — checks for `plain-crypto-js` directory (presence = compromise, even if clean)
3. **Package caches** — npm, Yarn, pnpm, Bun
4. **Malware artifacts** — OS-specific trojan paths + campaign files
5. **C2 connections** — `sfrclak.com` / `142.11.206.73`
6. **Credential files** — lists what may have been exfiltrated
7. **Hardening** — checks `ignore-scripts`, recommends `overrides` block

## The false positive trap

Our first version had a bug: the regex `"1.14.1"` matched **any** package at that version — `serve-static@1.14.1`, `@webassemblyjs/ast@1.14.1`, etc. One machine showed 48 "critical" hits that were all false positives.

The fix: two-phase detection. Phase 1 searches for definitive markers (`plain-crypto-js`, `openclaw-qbot`). Phase 2 does contextual grep — only flags version `1.14.1` when it appears within 2 lines of `"axios"` in the lock file.

## Anti-forensic detection

The coolest (scariest?) detail from [StepSecurity's analysis](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan): after the malware runs, it replaces its `package.json` with a stub that reports version `4.2.0` instead of `4.2.1`. Running `npm list` post-infection shows the wrong version.

Our scanner catches this by checking for the **directory existence** regardless of what `package.json` says inside.

## Compatible with everything

- macOS Catalina → Sequoia (Intel + Apple Silicon)
- Linux (any distro)
- Bash 3.2+ (stock macOS bash)
- Works with or without Node.js installed

## Get it

GitHub: [booklib-ai/dispatch](https://github.com/booklib-ai/dispatch)

This is dispatch #001 from **booklib-ai** — we'll publish same-day analysis + tools for future supply chain incidents. Star the repo if you want to stay updated.

---

*Also from booklib-ai: [skills](https://github.com/booklib-ai/skills) — plug-and-play expertise for AI coding agents — structured engineering skills distributed via npm that integrate with Claude Code, Cursor, and any MCP-compatible tool.*
