"""Self-contained tool manager.

Downloads the LATEST official release binary for each recon/scan tool this
pipeline orchestrates, straight from each project's GitHub Releases API,
into ./bin — no system-wide install, no Go toolchain, no package manager
required. Tools already on the system PATH are still picked up too; this
just removes the "go install this yourself" step entirely.

Versions are resolved dynamically (not hardcoded) by querying each repo's
`releases/latest` API endpoint and picking the asset that matches the
current OS/architecture — hardcoded version pins go stale within weeks for
fast-moving tools like these, which would silently break this exact
automation.

Covers: subfinder, httpx, naabu, katana, nuclei, ffuf — all single static
binaries (ProjectDiscovery's suite + ffuf), no runtime dependencies.

nmap is deliberately NOT auto-installed here: it needs system packet-capture
drivers (libpcap/npcap) that can't be safely vendored. naabu is used as the
default, fully self-contained port scanner instead; nmap is used only as an
optional enrichment step if it's already on the system.
"""
import json
import os
import platform
import shutil
import stat
import tarfile
import urllib.request
import zipfile

BIN_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin"))

REPOS = {
    "subfinder": "projectdiscovery/subfinder",
    "httpx": "projectdiscovery/httpx",
    "naabu": "projectdiscovery/naabu",
    "katana": "projectdiscovery/katana",
    "nuclei": "projectdiscovery/nuclei",
    "ffuf": "ffuf/ffuf",
}

OS_KEYWORDS = {
    "linux": ["linux"],
    "darwin": ["macos", "darwin", "mac"],
    "windows": ["windows", "win"],
}
ARCH_KEYWORDS = {
    "amd64": ["amd64", "x86_64", "x64"],
    "arm64": ["arm64", "aarch64"],
}


def _current_os_arch():
    sys_os = platform.system().lower()  # linux / darwin / windows
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    return sys_os, arch


def _api_get(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": "scoperunner-setup",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _pick_asset(assets, sys_os, arch):
    os_kw = OS_KEYWORDS.get(sys_os, [sys_os])
    arch_kw = ARCH_KEYWORDS.get(arch, [arch])
    candidates = []
    for a in assets:
        name = a.get("name", "").lower()
        if not (name.endswith(".zip") or name.endswith(".tar.gz") or name.endswith(".tgz")):
            continue
        if "checksum" in name or name.endswith(".sig") or name.endswith(".pem"):
            continue
        if any(k in name for k in os_kw) and any(k in name for k in arch_kw):
            candidates.append(a)
    return candidates[0] if candidates else None


def _download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "scoperunner-setup"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)


def _extract_binary(archive_path, target_dir, tool_name, exe_name):
    """Pull the tool's executable out of the archive, whatever it's nested
    under, by matching on basename (case-insensitive, extension-agnostic)."""
    def matches(member_name):
        base = os.path.basename(member_name).lower()
        base_noext = base[:-4] if base.endswith(".exe") else base
        return base_noext == tool_name.lower()

    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as z:
            for name in z.namelist():
                if not name.endswith("/") and matches(name):
                    with z.open(name) as src, open(os.path.join(target_dir, exe_name), "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    return True
    elif archive_path.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path) as t:
            for member in t.getmembers():
                if member.isfile() and matches(member.name):
                    src = t.extractfile(member)
                    with open(os.path.join(target_dir, exe_name), "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    return True
    return False


def ensure_tool(name, log=print):
    os.makedirs(BIN_DIR, exist_ok=True)
    exe_name = name + (".exe" if platform.system() == "Windows" else "")
    dest_path = os.path.join(BIN_DIR, exe_name)
    if os.path.exists(dest_path):
        return dest_path
    if name not in REPOS:
        return None

    repo = REPOS[name]
    sys_os, arch = _current_os_arch()
    try:
        release = _api_get(f"https://api.github.com/repos/{repo}/releases/latest")
    except Exception as exc:
        log(f"{name}: could not reach GitHub releases API ({exc}) — skipping, will retry next run")
        return None

    asset = _pick_asset(release.get("assets", []), sys_os, arch)
    if not asset:
        log(f"{name}: no matching release asset found for {sys_os}/{arch} — see {repo} releases page manually")
        return None

    version = release.get("tag_name", "latest")
    log(f"downloading {name} {version} for {sys_os}/{arch} ...")
    tmp_path = os.path.join(BIN_DIR, asset["name"])
    try:
        _download(asset["browser_download_url"], tmp_path)
        ok = _extract_binary(tmp_path, BIN_DIR, name, exe_name)
        os.remove(tmp_path)
        if not ok:
            log(f"  could not locate {name} binary inside {asset['name']}")
            return None
        st = os.stat(dest_path)
        os.chmod(dest_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        log(f"  {name} {version} ready")
        return dest_path
    except Exception as exc:
        log(f"  failed to fetch {name}: {exc}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return None


def ensure_all(log=print):
    return {name: ensure_tool(name, log) for name in REPOS}


if __name__ == "__main__":
    ensure_all()
