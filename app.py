"""Local-only web UI for the recon → scan → report pipeline.

Run with `python app.py` (or via start.sh / start.bat). A browser tab opens
automatically at http://127.0.0.1:8765 — nothing here listens on any
interface other than localhost. On first run it also kicks off a background
download of the bundled recon/scan tool binaries (see pipeline/setup_tools.py)
so nothing needs to be installed by hand.
"""
import os
import threading
import time
import webbrowser

from flask import Flask, abort, jsonify, render_template, request, send_from_directory

from pipeline import runner, tools, setup_tools

app = Flask(__name__)
PORT = 8765

SETUP_STATE = {"running": False, "log": [], "done": False}
_setup_lock = threading.Lock()


def _setup_log(msg):
    with _setup_lock:
        SETUP_STATE["log"].append(f"[{time.strftime('%H:%M:%S')}] {msg}")


def _run_setup():
    with _setup_lock:
        SETUP_STATE["running"] = True
    setup_tools.ensure_all(log=_setup_log)
    with _setup_lock:
        SETUP_STATE["running"] = False
        SETUP_STATE["done"] = True


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/tools-status")
def tools_status():
    return jsonify(tools.tools_status())


@app.route("/api/setup-status")
def setup_status():
    with _setup_lock:
        return jsonify(dict(SETUP_STATE))


@app.route("/api/setup-tools", methods=["POST"])
def trigger_setup():
    with _setup_lock:
        already_running = SETUP_STATE["running"]
    if not already_running:
        threading.Thread(target=_run_setup, daemon=True).start()
    return jsonify({"started": not already_running})


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(force=True) or {}
    scope_text = (data.get("scope") or "").strip()
    authorized = bool(data.get("authorized"))
    options = data.get("options") or {}

    if not authorized:
        return jsonify({"error": "You must confirm authorization before starting a scan."}), 400
    if not scope_text:
        return jsonify({"error": "Scope cannot be empty."}), 400

    scan_id = runner.start_scan(scope_text, options)
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    state = runner.get_state(scan_id)
    if not state:
        abort(404)
    return jsonify(state)


@app.route("/api/scan/<scan_id>/report.<fmt>")
def scan_report(scan_id, fmt):
    if fmt not in ("md", "html", "json"):
        abort(404)
    fname = {"md": "report.md", "html": "report.html", "json": "raw.json"}[fmt]
    workdir = os.path.join(runner.BASE_DIR, scan_id)
    if not os.path.exists(os.path.join(workdir, fname)):
        abort(404)
    return send_from_directory(workdir, fname)


def _open_browser():
    webbrowser.open(f"http://127.0.0.1:{PORT}")


if __name__ == "__main__":
    threading.Timer(1.0, _open_browser).start()
    threading.Thread(target=_run_setup, daemon=True).start()
    app.run(host="127.0.0.1", port=PORT, debug=False)
