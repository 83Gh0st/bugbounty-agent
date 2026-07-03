"""Thin wrappers around external recon/scanning tools.

Resolves each tool from the app's own ./bin (populated by setup_tools.py)
first, falling back to the system PATH. Every function degrades gracefully:
if a tool isn't available it logs why and returns an empty result instead of
raising. This module never implements vulnerability checks itself —
detection logic comes from the tools' own maintained rule/template sets
(e.g. nuclei's community templates), which is the standard, auditable
approach for this kind of automation.
"""
import json
import os
import shutil
import subprocess

from .setup_tools import BIN_DIR

INSTALL_HINTS = {
    "subfinder": "auto-managed — fetched into ./bin on first run",
    "httpx": "auto-managed — fetched into ./bin on first run",
    "naabu": "auto-managed — fetched into ./bin on first run",
    "katana": "auto-managed — fetched into ./bin on first run",
    "nuclei": "auto-managed — fetched into ./bin on first run",
    "ffuf": "auto-managed — fetched into ./bin on first run",
    "nmap": "optional, system-installed — brew install nmap / sudo apt install nmap",
}


def which(tool):
    exe = tool + (".exe" if os.name == "nt" else "")
    local = os.path.join(BIN_DIR, exe)
    if os.path.exists(local) and os.access(local, os.X_OK):
        return local
    return shutil.which(tool)


def tools_status():
    return {t: bool(which(t)) for t in INSTALL_HINTS}


def _run(cmd, timeout, log, input_text=None):
    log(f"$ {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout)
        if proc.returncode not in (0, None) and proc.stderr:
            log(f"  (exit {proc.returncode}) {proc.stderr.strip()[:300]}")
        return proc.stdout or ""
    except subprocess.TimeoutExpired:
        log(f"  timed out after {timeout}s, continuing with partial/no results")
        return ""
    except FileNotFoundError:
        log("  tool binary not found")
        return ""


def run_subfinder(domain, log, timeout=120):
    bin_ = which("subfinder")
    if not bin_:
        log(f"subfinder unavailable ({INSTALL_HINTS['subfinder']}) — skipping subdomain enum for {domain}")
        return []
    out = _run([bin_, "-d", domain, "-silent"], timeout, log)
    return sorted({l.strip() for l in out.splitlines() if l.strip()})


def run_httpx(hosts, log, timeout=120, rate_limit=80):
    if not hosts:
        return []
    bin_ = which("httpx")
    if not bin_:
        log(f"httpx unavailable ({INSTALL_HINTS['httpx']}) — skipping liveness probe")
        return []
    cmd = [bin_, "-silent", "-json", "-rl", str(rate_limit), "-timeout", "8",
           "-tech-detect", "-status-code", "-title", "-follow-redirects"]
    out = _run(cmd, timeout, log, input_text="\n".join(hosts))
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def run_katana(url, log, timeout=180, depth=2, rate_limit=80):
    """JS-aware crawl for endpoint discovery — more thorough than a plain
    spider, useful for finding API routes a brute-force wordlist would miss."""
    bin_ = which("katana")
    if not bin_:
        log(f"katana unavailable ({INSTALL_HINTS['katana']}) — skipping crawl for {url}")
        return []
    cmd = [bin_, "-u", url, "-silent", "-jc", "-d", str(depth), "-rl", str(rate_limit)]
    out = _run(cmd, timeout, log)
    return sorted({l.strip() for l in out.splitlines() if l.strip()})


def run_naabu(target, log, timeout=180, top_ports=100, rate_limit=1000):
    """Fast, self-contained port scan (no libpcap/npcap dependency, unlike nmap)."""
    bin_ = which("naabu")
    if not bin_:
        log(f"naabu unavailable ({INSTALL_HINTS['naabu']}) — skipping port scan for {target}")
        return {"target": target, "ports": [], "raw": ""}
    cmd = [bin_, "-host", target, "-top-ports", str(top_ports), "-silent", "-json", "-rate", str(rate_limit)]
    out = _run(cmd, timeout, log)
    ports = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            ports.append({"port": str(d.get("port", "")), "protocol": "tcp", "service": "", "version": ""})
        except json.JSONDecodeError:
            continue
    return {"target": target, "ports": ports, "raw": out}


def run_nmap_enrich(target, ports, log, timeout=180):
    """Optional: if the user already has nmap installed, use it to attach
    service/version info to ports naabu already found. Never required."""
    if not ports or not which("nmap"):
        return []
    port_list = ",".join(p["port"] for p in ports if p.get("port"))
    if not port_list:
        return []
    out = _run(["nmap", "-sV", "-Pn", "-p", port_list, "-oG", "-", target], timeout, log)
    enriched = []
    for line in out.splitlines():
        if line.startswith("Host:") and "Ports:" in line:
            try:
                section = line.split("Ports:")[1].split("\t")[0]
                for entry in section.split(","):
                    f = entry.strip().split("/")
                    if len(f) >= 5 and f[1] == "open":
                        enriched.append({"port": f[0], "protocol": f[2], "service": f[4],
                                          "version": f[6] if len(f) > 6 else ""})
            except Exception:
                pass
    return enriched


def run_nuclei(urls, log, severity, exclude_tags, rate_limit=80, timeout=900):
    """Vulnerability detection via nuclei's maintained community templates.
    OAST/Interactsh is left ENABLED (no -ni flag) so blind vulnerabilities
    (blind SSRF, blind command injection, blind XXE) get confirmed via a
    real out-of-band callback rather than just a heuristic match — this is
    the safe, non-destructive way to prove a finding is genuinely
    exploitable without taking any further action against the target."""
    if not urls:
        return []
    bin_ = which("nuclei")
    if not bin_:
        log(f"nuclei unavailable ({INSTALL_HINTS['nuclei']}) — skipping vulnerability scan")
        return []
    cmd = [bin_, "-silent", "-jsonl", "-severity", severity, "-rl", str(rate_limit), "-timeout", "10"]
    if exclude_tags:
        cmd += ["-etags", exclude_tags]
    log(f"$ {' '.join(cmd)}  (scanning {len(urls)} live target(s), OAST confirmation enabled)")
    out = _run(cmd, timeout, log, input_text="\n".join(urls))
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def run_ffuf(url, wordlist_path, log, rate_limit=40, timeout=300):
    bin_ = which("ffuf")
    if not bin_:
        log(f"ffuf unavailable ({INSTALL_HINTS['ffuf']}) — skipping content discovery for {url}")
        return []
    if not os.path.exists(wordlist_path):
        log(f"wordlist not found at {wordlist_path} — skipping content discovery")
        return []
    target = url.rstrip("/") + "/FUZZ"
    cmd = [bin_, "-u", target, "-w", wordlist_path,
           "-mc", "200,204,301,302,307,401,403",
           "-rate", str(rate_limit), "-of", "json", "-o", "-", "-s"]
    out = _run(cmd, timeout, log)
    try:
        return json.loads(out).get("results", []) if out.strip() else []
    except json.JSONDecodeError:
        return []
