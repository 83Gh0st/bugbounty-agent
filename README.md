# ScopeRunner

A local, single-operator web console for **authorized** bug bounty recon, scanning, and reporting.

Give it a scope; it runs subdomain enumeration, liveness probing, a JS-aware crawl, optional port scanning, vulnerability scanning (via nuclei's community-maintained detection templates, with out-of-band confirmation for blind vulnerabilities), optional content discovery, and writes a structured Markdown/HTML report — all on your own machine. Nothing leaves localhost except the tools' own requests to your declared targets.

> **Every recon/scan tool is self-managed.** On first run, ScopeRunner downloads the latest official release binary for `subfinder`, `httpx`, `naabu`, `katana`, `nuclei`, and `ffuf` straight from each project's GitHub Releases into `./bin` — no manual installs, no Go toolchain, no package manager. See [How tool management works](#how-tool-management-works).

---

## Table of Contents

- [⚠️ Before You Use This — Read This Section](#️-before-you-use-this--read-this-section)
- [What It Actually Does](#what-it-actually-does)
- [How Tool Management Works](#how-tool-management-works)
- [Running It](#running-it)
- [Scope Syntax](#scope-syntax)
- [Intensity Presets](#intensity-presets)
- [Extending It](#extending-it)
- [Limitations](#limitations)

---

## ⚠️ Before You Use This — Read This Section

**Only point this at targets you are explicitly authorized to test.** That means:

- A bug bounty program whose published scope covers the target,
- Your own infrastructure, or
- A signed pentest engagement letter.

Running active scans (port scans, vulnerability templates, content discovery) against anything else is unauthorized access in most jurisdictions, full stop. The authorization checkbox in the UI is a reminder, not a legal shield — **the responsibility for what you point this at is yours.**

### Scope of automation

This tool does not contain exploit code, and deliberately **stops at detection**.

- Vulnerability detection is delegated entirely to [nuclei](https://github.com/projectdiscovery/nuclei)'s publicly maintained template library.
- For *blind* vulnerabilities (blind SSRF, blind command injection, blind XXE), nuclei's built-in OAST/Interactsh client stays enabled, so those findings are confirmed by an actual out-of-band callback rather than a guess — that's the legitimate way to prove a blind finding is real without taking any further action against the target.
- What this tool will **never** do is go further than that: actually executing payloads to extract data, gain a shell, or otherwise prove "full compromise" crosses from authorized detection into actual intrusion — which is both outside nearly every bug bounty program's rules of engagement and not something this project will automate.

**Treat every finding as a lead — validate manually before submitting anything to a program.**

---

## What It Actually Does

```
Scope → Recon → Probe → Crawl → [Ports] → Vuln Scan → [Content] → Report
```

| Stage | Tool | Description |
|---|---|---|
| 1. **Scope** | — | Parses your input (domains, `*.wildcard` subdomains, IPs, `/24`-or-smaller CIDR blocks). Anything that doesn't match is rejected. |
| 2. **Recon** | `subfinder` | Enumerates subdomains of any domain roots in scope. Anything discovered outside your declared scope is recorded in the report but never actively touched. |
| 3. **Probe** | `httpx` | Checks which hosts are alive, fingerprints tech stack, grabs titles/status codes. |
| 4. **Crawl** *(default: on)* | `katana` | JS-aware crawl of live targets to find API routes and endpoints a wordlist alone would miss. Every discovered URL is re-checked against scope before being scanned. |
| 5. **Ports** *(default: off)* | `naabu` | Scans your declared IP/CIDR scope and resolved hosts. Naabu is a self-contained static binary (unlike nmap, no libpcap/npcap driver needed), so it fits the fully-managed model. If nmap is *also* installed, its service/version detection enriches naabu's results — but it's never required. |
| 6. **Vuln Scan** | `nuclei` | Runs detection templates against every live web target *and* every in-scope crawled endpoint, filtered by severity per your chosen intensity. OAST confirmation is on for blind checks. |
| 7. **Content** *(default: off)* | `ffuf` | Brute-forces a small built-in wordlist (`wordlists/common.txt`) against live targets. |
| 8. **Report** | — | Everything is aggregated into `report.md` / `report.html` / `raw.json`, grouped by severity, with methodology and recommendations. |

---

## How Tool Management Works

`pipeline/setup_tools.py` queries each tool's GitHub `releases/latest` API endpoint at runtime (no hardcoded version numbers — those go stale within weeks for fast-moving tools like these), picks the release asset matching your OS/architecture, downloads it, and extracts the binary into `./bin`.

- This kicks off automatically in the background the moment you run `start.sh` / `start.bat`.
- Tool status chips in the UI update live as each binary becomes available — usually well before you've finished typing your scope.
- If a tool is already on your system `PATH`, it's used as-is and never re-downloaded.
- If GitHub is unreachable (offline, firewalled, rate-limited), the affected stage is skipped with a clear log message — the rest of the pipeline still runs, and it retries automatically next time you start the app.

> **Note on `nmap`:** it's the one exception — it needs OS-level packet-capture drivers that can't be safely auto-installed, so it stays optional:
> ```bash
> brew install nmap        # macOS
> sudo apt install nmap    # Debian/Ubuntu
> ```
> Install it if you want its service/version enrichment.

---

## Running It

### macOS / Linux

```bash
./start.sh
```

### Windows

```bat
start.bat
```

First run creates a Python virtual environment, installs Flask, and starts downloading the recon/scan binaries in the background. Your browser opens automatically to [`http://127.0.0.1:8765`](http://127.0.0.1:8765) — the server only listens on localhost. Tool downloads happen once; subsequent runs start instantly.

---

## Scope Syntax

```
example.com          # apex domain only
*.example.com         # domain + all subdomains
203.0.113.10          # single IP
203.0.113.0/24        # CIDR block, max /24 expanded for safety
# lines starting with # are comments
```

---

## Intensity Presets

| Preset | Rate limit | nuclei severities |
|---|---|---|
| **Stealthy** | 20 req/s | high, critical |
| **Normal** | 80 req/s | medium, high, critical |
| **Aggressive** | 200 req/s | info, low, medium, high, critical (drops the dos/intrusive template exclusion) |

---

## Extending It

- **Add a tool** — Add it to `REPOS` in `pipeline/setup_tools.py` (if it ships GitHub release binaries) or check `shutil.which()` for it, then write a wrapper in `pipeline/tools.py` following the existing pattern, and call it from `pipeline/runner.py`.
- **Swap the wordlist** — Replace `wordlists/common.txt`, or point `run_ffuf()` at a SecLists path if you have it installed.
- **Custom nuclei templates** — Drop them anywhere and add `-t <path>` to the nuclei command in `tools.py`.
- **AI-assisted triage** — Deliberately not included by default. If you want it, the natural place is a post-processing step in `pipeline/report.py` that sends `raw.json` findings to an LLM for prioritization/summarization before rendering — keep a human in the loop before anything gets reported to a program.

---



- Triage is rule-based (severity field from nuclei), not AI-assisted — you'll want to read the actual findings.
- This automates *known-pattern* detection and blind-vuln confirmation well. It is not, and won't become, an exploitation framework — it's not a substitute for manual testing of business logic, auth flows, IDOR, and access control, which is exactly why the report keeps saying so.
