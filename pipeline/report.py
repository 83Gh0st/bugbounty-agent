"""Aggregates raw tool output into a structured, human-readable report."""
import datetime
import html as _html

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info", "unknown": "Unknown",
}


def summarize(nuclei_findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in nuclei_findings:
        sev = (f.get("info", {}).get("severity") or "unknown").lower()
        counts[sev if sev in counts else "unknown"] += 1
    counts["total"] = len(nuclei_findings)
    return counts


def _group(nuclei_findings):
    grouped = {s: [] for s in SEVERITY_ORDER}
    for f in nuclei_findings:
        sev = (f.get("info", {}).get("severity") or "unknown").lower()
        grouped.setdefault(sev if sev in grouped else "unknown", []).append(f)
    return grouped


def build(raw):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    nuclei_findings = raw.get("nuclei", [])
    grouped = _group(nuclei_findings)
    counts = summarize(nuclei_findings)
    opts = raw.get("options", {})

    L = []
    L.append("# Web Application Penetration Test Report")
    L.append("")
    L.append(f"**Scan ID:** {raw['scan_id']}  ")
    L.append(f"**Generated:** {now}  ")
    L.append("**Authorization:** Operator confirmed explicit authorization to test the scope below "
              "before this scan was started.")
    L.append("")
    L.append("## Scope")
    L.append("```")
    L.append(raw["scope_text"].strip())
    L.append("```")
    if raw.get("out_of_scope_found"):
        L.append("")
        L.append(f"_{len(raw['out_of_scope_found'])} subdomain(s) were discovered outside the "
                  f"declared scope and were excluded from all active testing._")

    L.append("")
    L.append("## Executive Summary")
    L.append("")
    L.append("| Severity | Count |")
    L.append("|---|---|")
    for s in SEVERITY_ORDER:
        if counts[s]:
            L.append(f"| {SEVERITY_LABEL[s]} | {counts[s]} |")
    L.append(f"| **Total** | **{counts['total']}** |")

    L.append("")
    L.append("## Methodology")
    L.append(f"- Intensity profile: **{opts.get('intensity', 'normal')}**")
    L.append("- Passive subdomain enumeration: subfinder")
    L.append("- Liveness / technology fingerprinting: httpx")
    L.append(f"- Port scanning: {'naabu, with nmap enrichment if locally available (enabled)' if opts.get('port_scan') else 'disabled for this run'}")
    L.append("- Vulnerability scanning: nuclei, community detection templates "
              "(active-exploit/DoS-tagged templates excluded unless aggressive mode was selected)")
    L.append("- Blind vulnerability confirmation: out-of-band (OAST/Interactsh) callbacks enabled — "
              "blind SSRF, blind command injection, and blind XXE findings below are confirmed by an "
              "actual callback from the target, not just a heuristic match")
    L.append(f"- Deep crawl: {'katana (enabled)' if opts.get('deep_crawl', True) else 'disabled for this run'}")
    L.append(f"- Content discovery: {'ffuf (enabled)' if opts.get('content_discovery') else 'disabled for this run'}")
    L.append(f"- Live web targets tested: {len(raw.get('httpx', []))}")

    L.append("")
    L.append("## Findings")
    if not nuclei_findings:
        L.append("")
        L.append("No findings were reported by the automated vulnerability scanning stage. This does "
                  "not guarantee the target is free of vulnerabilities — manual testing of business "
                  "logic, authentication/authorization flows, and access control is still recommended "
                  "(see Recommendations below).")
    for sev in SEVERITY_ORDER:
        items = grouped.get(sev, [])
        if not items:
            continue
        L.append("")
        L.append(f"### {SEVERITY_LABEL[sev]} ({len(items)})")
        for f in items:
            info = f.get("info", {})
            name = info.get("name", f.get("template-id", "unnamed finding"))
            matched = f.get("matched-at") or f.get("host", "")
            desc = (info.get("description") or "").strip().replace("\n", " ")
            refs = info.get("reference") or []
            refs = refs if isinstance(refs, list) else [refs]
            L.append("")
            L.append(f"**{name}**  ")
            L.append(f"- Target: `{matched}`")
            L.append(f"- Template: `{f.get('template-id', 'n/a')}`")
            if desc:
                L.append(f"- Description: {desc[:400]}")
            if refs:
                L.append(f"- Reference: {', '.join(refs[:3])}")

    if raw.get("katana"):
        L.append("")
        L.append(f"## Crawled Endpoints ({len(raw['katana'])})")
        L.append("")
        L.append("_Discovered via JS-aware crawl. All endpoints below were verified in-scope before "
                  "being included in vulnerability scanning._")
        for u in raw["katana"][:200]:
            L.append(f"- {u}")
        if len(raw["katana"]) > 200:
            L.append(f"- _...and {len(raw['katana']) - 200} more, see raw.json_")

    if raw.get("nmap"):
        any_ports = any(e.get("ports") for e in raw["nmap"])
        if any_ports:
            L.append("")
            L.append("## Open Ports / Services")
            L.append("")
            L.append("_Scanned with naabu; service/version columns are filled in only if nmap was "
                      "also available locally for enrichment._")
            for entry in raw["nmap"]:
                if not entry.get("ports"):
                    continue
                L.append("")
                L.append(f"**{entry['target']}**")
                L.append("")
                L.append("| Port | Protocol | Service | Version |")
                L.append("|---|---|---|---|")
                for p in entry["ports"]:
                    L.append(f"| {p['port']} | {p['protocol']} | {p['service']} | {p.get('version','')} |")

    if raw.get("ffuf"):
        if any(v for v in raw["ffuf"].values()):
            L.append("")
            L.append("## Discovered Content")
            for url, hits in raw["ffuf"].items():
                if not hits:
                    continue
                L.append("")
                L.append(f"**{url}**")
                for h in hits[:30]:
                    path = h.get("input", {}).get("FUZZ", h.get("url", ""))
                    L.append(f"- `{path}` ({h.get('status')}, {h.get('length')} bytes)")

    L.append("")
    L.append("## Recommendations")
    L.append("")
    L.append("- Triage and manually validate every Critical/High finding before reporting it to a "
              "bug bounty program — automated scanners produce false positives, and unverified "
              "reports waste a triager's time and your reputation.")
    L.append("- Manually test what automated scanning is weak at: authentication and authorization "
              "logic, multi-step business workflows, IDOR, race conditions, and privilege escalation.")
    L.append("- Re-run this pipeline as scope or application code changes; keep nuclei templates "
              "updated (`nuclei -update-templates`) so detection stays current.")

    L.append("")
    L.append("## Discovered Assets")
    L.append("")
    for h in raw.get("discovered_hosts", []):
        L.append(f"- {h}")

    md = "\n".join(L)
    html_doc = _md_to_html_shell(md, raw["scan_id"])
    return md, html_doc


def _md_to_html_shell(md_text, scan_id):
    body, in_table = [], False
    for line in md_text.splitlines():
        esc = _html.escape(line)
        if line.startswith("### "):
            body.append(f"<h3>{esc[4:]}</h3>")
        elif line.startswith("## "):
            body.append(f"<h2>{esc[3:]}</h2>")
        elif line.startswith("# "):
            body.append(f"<h1>{esc[2:]}</h1>")
        elif line.startswith("|"):
            if set(line.replace("|", "").strip()) <= {"-", " "}:
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            tag = "td" if in_table else "th"
            row = "".join(f"<{tag}>{_html.escape(c)}</{tag}>" for c in cells)
            body.append(("<tr>" if in_table else "<table><tr>") + row + "</tr>")
            in_table = True
            continue
        else:
            if in_table:
                body.append("</table>")
                in_table = False
            stripped = line.strip()
            if stripped.startswith("- "):
                body.append(f"<li>{esc.strip()[2:]}</li>")
            elif stripped == "```":
                body.append("<hr/>")
            elif stripped.startswith("**") and stripped.endswith("**") and len(stripped) > 4:
                body.append(f"<p><strong>{esc.strip().strip('*')}</strong></p>")
            elif stripped:
                body.append(f"<p>{esc}</p>")
    if in_table:
        body.append("</table>")
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        f"<title>Report {scan_id}</title>"
        '<link rel="stylesheet" href="/static/style.css"></head>'
        '<body class="report-body"><div class="report-container">'
        + "".join(body) +
        "</div></body></html>"
    )
