"""Pipeline orchestration.

Each scan runs in a background thread. State (log lines, current stage,
progress, summary) lives in the in-memory SCANS registry so the UI can poll
it, and final artifacts are written to a per-scan folder under ./scans/.

Scope is enforced throughout, not just at input time: subdomains found
during recon AND endpoints found during crawling that fall outside the
declared scope are recorded but never passed to any active tool (port scan,
nuclei, ffuf).
"""
import json
import os
import threading
import time
import uuid
from urllib.parse import urlparse

from . import tools, report
from .scope import Scope

SCANS = {}
_lock = threading.Lock()
BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scans")

INTENSITY_PRESETS = {
    "stealthy":   {"rate": 20,  "nuclei_severity": "high,critical"},
    "normal":     {"rate": 80,  "nuclei_severity": "medium,high,critical"},
    "aggressive": {"rate": 200, "nuclei_severity": "info,low,medium,high,critical"},
}


def _new_state():
    return {
        "status": "running", "stage": "validate", "progress": 0, "log": [],
        "started": time.time(), "finished": None, "summary": None, "error": None,
    }


def start_scan(scope_text, options):
    scan_id = uuid.uuid4().hex[:12]
    with _lock:
        SCANS[scan_id] = _new_state()
    workdir = os.path.join(BASE_DIR, scan_id)
    os.makedirs(workdir, exist_ok=True)
    threading.Thread(target=_run, args=(scan_id, scope_text, options, workdir), daemon=True).start()
    return scan_id


def get_state(scan_id):
    with _lock:
        return SCANS.get(scan_id)


def _log(scan_id, msg):
    with _lock:
        SCANS[scan_id]["log"].append(f"[{time.strftime('%H:%M:%S')}] {msg}")


def _set(scan_id, **kw):
    with _lock:
        SCANS[scan_id].update(kw)


def _run(scan_id, scope_text, options, workdir):
    try:
        preset = INTENSITY_PRESETS.get(options.get("intensity", "normal"), INTENSITY_PRESETS["normal"])
        scope = Scope(scope_text)
        if scope.is_empty():
            raise ValueError("Scope is empty or contains no valid entries")
        if scope.invalid:
            _log(scan_id, f"ignoring invalid scope line(s): {', '.join(scope.invalid)}")

        _set(scan_id, stage="recon", progress=8)
        _log(scan_id, f"scope loaded: {len(scope.entries)} entr(y/ies), {len(scope.domain_roots)} domain root(s)")

        discovered, out_of_scope = set(), []
        for domain in scope.domain_roots:
            discovered.add(domain)
            for s in tools.run_subfinder(domain, lambda m: _log(scan_id, m)):
                if scope.host_in_scope(s):
                    discovered.add(s)
                else:
                    out_of_scope.append(s)
        if out_of_scope:
            _log(scan_id, f"{len(out_of_scope)} discovered subdomain(s) fall outside scope — excluded from active testing")

        ip_targets = [e.value for e in scope.ip_ranges if e.kind == "ip"]
        for e in scope.ip_ranges:
            if e.kind == "cidr" and e.network.num_addresses <= 256:
                ip_targets.extend(str(ip) for ip in e.network.hosts())
            elif e.kind == "cidr":
                _log(scan_id, f"{e.value} is larger than /24 — skipping host expansion for safety")

        _set(scan_id, stage="probe", progress=22)
        all_hosts = sorted(discovered) + ip_targets
        httpx_results = tools.run_httpx(all_hosts, lambda m: _log(scan_id, m), rate_limit=preset["rate"])
        live_targets = [r["url"] for r in httpx_results if r.get("url")]
        _log(scan_id, f"{len(live_targets)} live web target(s) found")

        crawled_urls = []
        if options.get("deep_crawl", True):
            _set(scan_id, stage="crawl", progress=35)
            seen_out_of_scope = 0
            for url in live_targets:
                for found in tools.run_katana(url, lambda m: _log(scan_id, m)):
                    host = urlparse(found).hostname or ""
                    if scope.host_in_scope(host) or scope.ip_in_scope(host) or any(host == d for d in scope.domain_roots):
                        crawled_urls.append(found)
                    else:
                        seen_out_of_scope += 1
            crawled_urls = sorted(set(crawled_urls))
            _log(scan_id, f"crawl found {len(crawled_urls)} in-scope endpoint(s)"
                           + (f", {seen_out_of_scope} out-of-scope link(s) ignored" if seen_out_of_scope else ""))
        else:
            _log(scan_id, "deep crawl disabled, skipping")

        nmap_supplemented = []
        if options.get("port_scan"):
            _set(scan_id, stage="ports", progress=48)
            port_targets = set(ip_targets)
            for r in httpx_results:
                h = r.get("host") or r.get("input")
                if h:
                    port_targets.add(h)
            naabu_results = []
            for t in sorted(port_targets):
                res = tools.run_naabu(t, lambda m: _log(scan_id, m))
                if res["ports"]:
                    enrichment = tools.run_nmap_enrich(t, res["ports"], lambda m: _log(scan_id, m))
                    if enrichment:
                        res["ports"] = enrichment
                naabu_results.append(res)
            nmap_supplemented = naabu_results
        else:
            _log(scan_id, "port scan disabled, skipping")

        _set(scan_id, stage="vuln", progress=62)
        scan_targets = sorted(set(live_targets) | set(crawled_urls))
        exclude_tags = "" if options.get("intensity") == "aggressive" else "dos,intrusive,fuzz"
        nuclei_findings = tools.run_nuclei(
            scan_targets, lambda m: _log(scan_id, m),
            severity=preset["nuclei_severity"], exclude_tags=exclude_tags, rate_limit=preset["rate"],
        )
        _log(scan_id, f"{len(nuclei_findings)} finding(s) from nuclei (OAST confirmation enabled for blind checks)")

        ffuf_results = {}
        if options.get("content_discovery"):
            _set(scan_id, stage="content", progress=82)
            wordlist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists", "common.txt")
            for url in live_targets[:25]:
                ffuf_results[url] = tools.run_ffuf(url, wordlist, lambda m: _log(scan_id, m))
        else:
            _log(scan_id, "content discovery disabled, skipping")

        _set(scan_id, stage="report", progress=93)
        raw = {
            "scan_id": scan_id, "scope_text": scope_text, "options": options,
            "discovered_hosts": sorted(discovered), "out_of_scope_found": out_of_scope,
            "httpx": httpx_results, "katana": crawled_urls, "nmap": nmap_supplemented,
            "nuclei": nuclei_findings, "ffuf": ffuf_results,
        }
        with open(os.path.join(workdir, "raw.json"), "w") as f:
            json.dump(raw, f, indent=2)

        md, html_doc = report.build(raw)
        with open(os.path.join(workdir, "report.md"), "w") as f:
            f.write(md)
        with open(os.path.join(workdir, "report.html"), "w") as f:
            f.write(html_doc)

        _set(scan_id, status="complete", stage="done", progress=100,
             finished=time.time(), summary=report.summarize(nuclei_findings))
        _log(scan_id, "scan complete")
    except Exception as exc:
        _set(scan_id, status="error", error=str(exc))
        _log(scan_id, f"ERROR: {exc}")
