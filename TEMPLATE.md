# Dispatch Template

Create a new dispatch when a supply chain incident is discovered.

## Folder Structure

```
dispatches/YYYY-MM-DD-incident-name/
├── README.md     # Analysis (use template below)
├── scan.sh       # Scanner or remediation tool
```

## README.md Frontmatter

```markdown
# 🔴/🟡/🟢 Incident Name — Date

**Affected:** package@version  
**C2:** domain / IP  
**Window:** start–end UTC  
**Status:** Active / Resolved  

## TL;DR
## Who is at risk
## Scanner Tool
## Indicators of Compromise
## If You Are Compromised
## Sources
```

## Severity

- 🔴 Critical — active exploitation, RAT/backdoor
- 🟡 High — credential theft, data exfiltration
- 🟢 Medium — typosquat, dependency confusion
