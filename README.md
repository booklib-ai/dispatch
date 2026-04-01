# 🚨 booklib-ai/dispatch

**Security incidents analyzed. Tools shipped. Same day.**

When supply chain attacks hit the npm/PyPI/Maven ecosystem, we publish same-day analysis with working scanner tools — not just blog posts, but scripts you can run on your entire machine right now.

Part of the [booklib-ai](https://github.com/booklib-ai) open source organization.

---

## Latest Dispatches

| Date | Incident | Tool | Severity |
|------|----------|------|----------|
| 2026-04-01 | [Axios npm Supply Chain Attack](dispatches/2026-04-01-axios-supply-chain-attack/) | [scan.sh](dispatches/2026-04-01-axios-supply-chain-attack/scan.sh) | 🔴 Critical |

## Quick Start

Grab the latest scanner and run it:

```bash
curl -sL https://raw.githubusercontent.com/booklib-ai/dispatch/main/dispatches/2026-04-01-axios-supply-chain-attack/scan.sh -o scan.sh
chmod +x scan.sh
./scan.sh
```

## What makes this different

| Security vendor blogs | dispatch |
|---|---|
| Analysis only | Analysis + **working scanner tool** |
| Per-project scan (`snyk test`) | **Whole-laptop recursive scan** |
| Published 12–24h later | **Same-day response** |
| Enterprise/sales focus | **Developer-first, open source** |

## How it works

Each dispatch is a self-contained folder:

```
dispatches/2026-04-01-axios-supply-chain-attack/
├── README.md     # Full incident analysis
├── scan.sh       # Scanner tool (run on your machine)
```

Read the analysis on GitHub. Run the tool in your terminal. That's it.

## Contributing

Found a new supply chain incident? Built a scanner? PRs welcome.

See [TEMPLATE.md](TEMPLATE.md) for the dispatch format.

## Also from booklib-ai

- **[booklib-ai/skills](https://github.com/booklib-ai/skills)** — Classic software engineering books converted into structured AI agent skills. Install via npm, use with Claude Code, Cursor, and any MCP-compatible tool.

## License

MIT
