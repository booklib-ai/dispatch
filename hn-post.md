TITLE:
Show HN: Whole-laptop scanner for the Axios npm supply chain attack

URL:
https://github.com/booklib-ai/dispatch/tree/main/dispatches/2026-04-01-axios-supply-chain-attack

COMMENT (post after submitting):
We built this after the axios supply chain attack yesterday (March 31). Every security vendor published analysis, but their tools only scan per-project (snyk test, npm audit). This scans your entire machine recursively — all lock files, node_modules, package caches, OS-specific malware artifacts, and C2 connections — in one command.

Key things the scanner catches that others miss:

- Anti-forensic version spoofing (the malware reports version 4.2.0 after installing as 4.2.1)
- Directory-presence-only detection (even after self-cleanup, the plain-crypto-js folder existing = compromise)
- Two additional malicious packages from the Snyk advisory (@qqbrowser/openclaw-qbot, @shadanai/openclaw)
- Campaign-specific temp files (/tmp/6202033 on macOS, %TEMP%\6202033.vbs on Windows)

Works on macOS (Bash 3.2 compatible), Linux, with or without Node.js installed.

Sources: Socket.dev initial discovery, Snyk SNYK-JS-AXIOS-15850650, StepSecurity full technical analysis.
