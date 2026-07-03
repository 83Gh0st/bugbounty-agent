const STAGES = [
  { key: "validate", name: "Scope" },
  { key: "recon", name: "Recon" },
  { key: "probe", name: "Probe" },
  { key: "crawl", name: "Crawl" },
  { key: "ports", name: "Ports" },
  { key: "vuln", name: "Vuln Scan" },
  { key: "content", name: "Content" },
  { key: "report", name: "Report" },
];

const els = {
  toolChips: document.getElementById("toolChips"),
  setupBanner: document.getElementById("setupBanner"),
  scope: document.getElementById("scope"),
  intensity: document.getElementById("intensity"),
  deepCrawl: document.getElementById("deepCrawl"),
  portScan: document.getElementById("portScan"),
  contentDiscovery: document.getElementById("contentDiscovery"),
  authorized: document.getElementById("authorized"),
  startBtn: document.getElementById("startBtn"),
  errorBanner: document.getElementById("errorBanner"),
  pipeline: document.getElementById("pipeline"),
  terminal: document.getElementById("terminal"),
  resultsArea: document.getElementById("resultsArea"),
};

let pollTimer = null;

function renderPipeline(activeStage, options) {
  const crawlEnabled = options ? options.deep_crawl : els.deepCrawl.checked;
  const portsEnabled = options ? options.port_scan : els.portScan.checked;
  const contentEnabled = options ? options.content_discovery : els.contentDiscovery.checked;
  const activeIdx = STAGES.findIndex((s) => s.key === activeStage);

  els.pipeline.innerHTML = STAGES.map((s, i) => {
    let cls = "";
    if (s.key === "crawl" && !crawlEnabled) cls = "skipped";
    else if (s.key === "ports" && !portsEnabled) cls = "skipped";
    else if (s.key === "content" && !contentEnabled) cls = "skipped";
    else if (activeIdx === -1) cls = "";
    else if (i < activeIdx) cls = "done";
    else if (i === activeIdx) cls = "active";

    const node = `<div class="pipe-node ${cls}">
        <div class="ring">${i + 1}</div>
        <div class="name">${s.name}</div>
      </div>`;
    const line = i < STAGES.length - 1
      ? `<div class="pipe-line ${i < activeIdx ? "done" : ""}"></div>`
      : "";
    return node + line;
  }).join("");
}
renderPipeline(null, null);

async function loadToolStatus() {
  try {
    const res = await fetch("/api/tools-status");
    const data = await res.json();
    els.toolChips.innerHTML = Object.entries(data)
      .map(([tool, present]) =>
        `<span class="chip ${present ? "on" : "off"}"><span class="dot"></span>${tool}</span>`
      ).join("");
  } catch (e) {
    els.toolChips.innerHTML = `<span class="chip off"><span class="dot"></span>status unavailable</span>`;
  }
}
loadToolStatus();

async function pollSetup() {
  try {
    const res = await fetch("/api/setup-status");
    const state = await res.json();
    if (state.running) {
      const last = state.log.slice(-1)[0] || "preparing tools…";
      els.setupBanner.style.display = "flex";
      els.setupBanner.innerHTML = `<span class="spin"></span> Setting up tools (one-time): ${escapeHtml(last)}`;
    } else if (state.done) {
      els.setupBanner.style.display = "none";
      loadToolStatus();
      clearInterval(setupTimer);
    }
  } catch (e) {
    // transient — next poll will retry
  }
}
const setupTimer = setInterval(pollSetup, 2000);
pollSetup();

function showError(msg) {
  els.errorBanner.textContent = msg;
  els.errorBanner.style.display = "block";
}
function hideError() {
  els.errorBanner.style.display = "none";
}

function appendLog(lines) {
  if (!lines.length) return;
  els.terminal.innerHTML = lines.map((l) => `<span class="ln">${escapeHtml(l)}</span>`).join("\n");
  els.terminal.scrollTop = els.terminal.scrollHeight;
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

const SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];

function renderResults(summary, scanId, status) {
  if (status === "error") {
    els.resultsArea.innerHTML = `<div class="empty-note">Scan failed — see the log above.</div>`;
    return;
  }
  if (!summary) {
    els.resultsArea.innerHTML = `<div class="empty-note">Scan in progress…</div>`;
    return;
  }
  const cards = SEV_ORDER.filter((s) => summary[s]).map((s) =>
    `<div class="sev-card ${s}"><div class="n">${summary[s]}</div><div class="l">${s}</div></div>`
  ).join("");

  els.resultsArea.innerHTML = `
    <div class="summary-row">${cards || '<div class="empty-note">No findings reported.</div>'}</div>
    <div class="downloads">
      <a href="/api/scan/${scanId}/report.html" target="_blank">View report</a>
      <a href="/api/scan/${scanId}/report.md" download>Download Markdown</a>
      <a href="/api/scan/${scanId}/report.json" download>Download raw JSON</a>
    </div>
  `;
}

async function pollStatus(scanId) {
  try {
    const res = await fetch(`/api/scan/${scanId}/status`);
    if (!res.ok) return;
    const state = await res.json();

    renderPipeline(state.stage, null);
    appendLog(state.log || []);

    if (state.status === "complete" || state.status === "error") {
      clearInterval(pollTimer);
      els.startBtn.disabled = false;
      els.startBtn.textContent = "Start scan";
      renderResults(state.summary, scanId, state.status);
      if (state.error) showError(state.error);
    }
  } catch (e) {
    // transient — next poll will retry
  }
}

els.startBtn.addEventListener("click", async () => {
  hideError();
  const scope = els.scope.value.trim();
  if (!scope) { showError("Enter at least one scope entry."); return; }
  if (!els.authorized.checked) { showError("Confirm authorization before starting a scan."); return; }

  const options = {
    intensity: els.intensity.value,
    deep_crawl: els.deepCrawl.checked,
    port_scan: els.portScan.checked,
    content_discovery: els.contentDiscovery.checked,
  };

  els.startBtn.disabled = true;
  els.startBtn.textContent = "Running…";
  els.terminal.innerHTML = "";
  els.resultsArea.innerHTML = `<div class="empty-note">Scan in progress…</div>`;
  renderPipeline("validate", options);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope, authorized: true, options }),
    });
    const data = await res.json();
    if (!res.ok) {
      showError(data.error || "Could not start scan.");
      els.startBtn.disabled = false;
      els.startBtn.textContent = "Start scan";
      return;
    }
    pollTimer = setInterval(() => pollStatus(data.scan_id), 1500);
  } catch (e) {
    showError("Could not reach the local server.");
    els.startBtn.disabled = false;
    els.startBtn.textContent = "Start scan";
  }
});
