/**
 * app.js — WebTech Detector Frontend
 * ====================================
 * Handles tab navigation, scan requests, result rendering,
 * history management, and PDF export.
 */

"use strict";

// ── Config ────────────────────────────────────────────────────────────────────
const API_BASE = "";

// ── DOM refs ──────────────────────────────────────────────────────────────────
const urlInput      = document.getElementById("urlInput");
const scanBtn       = document.getElementById("scanBtn");
const loaderWrap    = document.getElementById("loaderWrap");
const loaderLabel   = document.getElementById("loaderLabel");
const loaderSteps   = document.getElementById("loaderSteps");
const resultsWrap   = document.getElementById("resultsWrap");
const errorBox      = document.getElementById("errorBox");
const errorMsg      = document.getElementById("errorMsg");
const statusDot     = document.getElementById("statusDot");
const statusText    = document.getElementById("statusText");
const exportPdfBtn  = document.getElementById("exportPdfBtn");
const newScanBtn    = document.getElementById("newScanBtn");
const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");

let currentScanId = null;

// ── Tab navigation ────────────────────────────────────────────────────────────
document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${tab}`).classList.add("active");

    if (tab === "history") loadHistory();
  });
});

// ── Scan trigger ──────────────────────────────────────────────────────────────
scanBtn.addEventListener("click", startScan);
urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") startScan();
});

async function startScan() {
  const url = urlInput.value.trim();
  if (!url) {
    showError("Please enter a URL to scan.");
    return;
  }

  hideAll();
  showLoader();
  setStatus("scanning", "SCANNING…");

  const steps = [
    "Resolving target host…",
    "Fetching page content…",
    "Detecting technologies…",
    "Analysing security headers…",
    "Scanning open ports…",
    "Checking SSL certificate…",
    "Calculating risk score…",
    "Generating report…",
  ];

  animateLoaderSteps(steps);

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(err || `HTTP ${response.status}`);
    }

    const data = await response.json();

    if (!data.success) {
      throw new Error(data.error || "Scan failed");
    }

    const result = data.data;
    currentScanId = result.id;
    hideLoader();
    renderResults(result);
    setStatus("ready", "SCAN COMPLETE");
  } catch (err) {
    hideLoader();
    showError(`Scan failed: ${err.message}`);
    setStatus("error", "ERROR");
  }
}

// ── Loader animation ──────────────────────────────────────────────────────────
function animateLoaderSteps(steps) {
  loaderSteps.innerHTML = "";
  steps.forEach((text, i) => {
    const el = document.createElement("div");
    el.className = "step";
    el.textContent = `[ … ] ${text}`;
    el.style.animationDelay = `${i * 0.4}s`;
    loaderSteps.appendChild(el);

    setTimeout(() => {
      el.textContent = `[ ✓ ] ${text}`;
      el.classList.add("done");
    }, (i + 1) * 400 + 200);
  });

  const labels = ["INITIALISING…", "FETCHING…", "DETECTING…", "ANALYSING…",
                   "PORT SCAN…", "SSL CHECK…", "SCORING…", "DONE"];
  labels.forEach((label, i) => {
    setTimeout(() => { loaderLabel.textContent = label; }, i * 400);
  });
}

// ── Result rendering ──────────────────────────────────────────────────────────
function renderResults(data) {
  const tech = data.technologies || {};
  const sec  = data.security     || {};

  // Risk banner
  renderRiskBanner(data.url, data.risk_level, data.risk_score, tech.scanned_at);

  // Tech grid
  renderTechGrid(tech);

  // Security findings (missing headers + port risks)
  renderFindings(sec);

  // SSL card
  renderSSL(tech.ssl || {});

  // Ports card
  renderPorts(tech.open_ports || []);

  // Recommendations
  renderRecommendations(sec.recommendations || []);

  resultsWrap.removeAttribute("hidden");
}

function renderRiskBanner(url, level, score, scannedAt) {
  document.getElementById("riskUrl").textContent = url;

  const badge = document.getElementById("riskLevelBadge");
  badge.textContent = (level || "Unknown").toUpperCase();
  badge.className = `risk-level-badge ${(level || "").toUpperCase()}`;

  const when = scannedAt ? new Date(scannedAt).toLocaleString() : "";
  document.getElementById("riskMeta").textContent = `Scanned at: ${when}`;

  // Gauge
  const pct  = Math.min(score, 100);
  const circ = 2 * Math.PI * 50; // radius = 50 → circumference ≈ 314
  const fill = document.getElementById("gaugeFill");
  const riskColors = { Low: "#00ff9d", Medium: "#ffbe0b", High: "#ff4d6d" };
  fill.style.stroke           = riskColors[level] || "#00c8ff";
  fill.style.strokeDasharray  = `${(pct / 100) * circ} ${circ}`;
  document.getElementById("gaugeValue").textContent = pct;
}

function renderTechGrid(tech) {
  const grid = document.getElementById("techGrid");
  grid.innerHTML = "";

  const categories = [
    { label: "CMS",                 key: "cms" },
    { label: "Frontend Frameworks", key: "frontend_frameworks" },
    { label: "Backend",             key: "backend_technologies" },
    { label: "Server / Hosting",    key: "server" },
    { label: "CDN",                 key: "cdn" },
    { label: "Analytics",           key: "analytics" },
  ];

  categories.forEach(({ label, key }) => {
    const items = tech[key] || [];
    const card  = document.createElement("div");
    card.className = "tech-card";
    card.innerHTML = `
      <div class="tech-card__category">${label}</div>
      <div class="tech-card__items">
        ${items.length
          ? items.map(t => `<span class="tech-tag">${escHtml(t)}</span>`).join("")
          : `<span class="tech-tag none">None detected</span>`
        }
      </div>`;
    grid.appendChild(card);
  });
}

function renderFindings(sec) {
  const grid = document.getElementById("findingsGrid");
  grid.innerHTML = "";

  const findings = [];

  // Missing security headers
  (sec.missing_headers || []).forEach(h => {
    findings.push({ title: h.header, desc: h.description, severity: h.severity });
  });

  // Protocol issues
  (sec.protocol_issues || []).forEach(p => {
    findings.push({ title: p.issue, desc: p.recommendation, severity: "High" });
  });

  // SSL issues
  (sec.ssl_issues || []).forEach(s => {
    findings.push({ title: "SSL Issue", desc: s, severity: "High" });
  });

  // Port risks
  (sec.open_port_risks || []).forEach(p => {
    findings.push({ title: `Port ${p.port} (${p.service})`, desc: p.risk, severity: p.severity });
  });

  // CMS warnings
  (sec.cms_warnings || []).forEach(w => {
    findings.push({ title: `${w.cms} Detected`, desc: w.note, severity: "Medium" });
  });

  if (findings.length === 0) {
    grid.innerHTML = `<p style="color:var(--text-dim); font-family:var(--font-mono); font-size:.85rem;">
      No critical findings detected.</p>`;
    return;
  }

  findings.forEach(({ title, desc, severity }) => {
    const card = document.createElement("div");
    card.className = `finding-card ${severity}`;
    card.innerHTML = `
      <div class="finding-card__header">
        <span class="finding-card__title">${escHtml(title)}</span>
        <span class="severity-badge ${severity}">${severity}</span>
      </div>
      <div class="finding-card__desc">${escHtml(desc)}</div>`;
    grid.appendChild(card);
  });
}

function renderSSL(ssl) {
  const body = document.getElementById("sslBody");
  if (!ssl.has_ssl) {
    body.innerHTML = `<div class="info-row-item">
      <span>HTTPS</span><span class="bad-tag">NOT ENABLED</span></div>`;
    return;
  }

  const validClass = ssl.valid ? "ok-tag" : "bad-tag";
  const expClass   = ssl.days_remaining !== null && ssl.days_remaining < 30 ? "warn-tag" : "ok-tag";

  body.innerHTML = `
    <div class="info-row-item"><span>HTTPS</span><span class="ok-tag">ENABLED</span></div>
    <div class="info-row-item"><span>Valid</span>
      <span class="${validClass}">${ssl.valid ? "YES" : "NO"}</span></div>
    <div class="info-row-item"><span>Issuer</span>
      <span>${escHtml(ssl.issuer || "Unknown")}</span></div>
    <div class="info-row-item"><span>Subject</span>
      <span>${escHtml(ssl.subject || "Unknown")}</span></div>
    <div class="info-row-item"><span>Expires</span>
      <span class="${expClass}">${ssl.days_remaining !== null
        ? `${ssl.days_remaining} days`
        : "Unknown"}</span></div>
    <div class="info-row-item"><span>Version</span>
      <span>${escHtml(ssl.version || "Unknown")}</span></div>
    ${ssl.error ? `<div class="info-row-item"><span>Error</span>
      <span class="bad-tag">${escHtml(ssl.error)}</span></div>` : ""}`;
}

function renderPorts(ports) {
  const body = document.getElementById("portsBody");
  if (ports.length === 0) {
    body.innerHTML = `<div class="info-row-item"><span>Open ports</span>
      <span class="ok-tag">None found</span></div>`;
    return;
  }

  const RISKY = ["FTP","Telnet","RDP","VNC","MongoDB","Redis","MySQL","PostgreSQL","SMB"];
  body.innerHTML = ports.map(p => {
    const cls = RISKY.includes(p.service) ? "bad-tag" : "ok-tag";
    return `<div class="info-row-item">
      <span>Port ${p.port}</span>
      <span class="${cls}">${escHtml(p.service)}</span>
    </div>`;
  }).join("");
}

function renderRecommendations(recs) {
  const list = document.getElementById("recsList");
  list.innerHTML = "";

  if (recs.length === 0) {
    list.innerHTML = `<p class="empty-state">No recommendations — great security posture! ✓</p>`;
    return;
  }

  recs.forEach((rec, i) => {
    const item = document.createElement("div");
    item.className = "rec-item";
    item.style.animationDelay = `${i * 0.05}s`;
    item.innerHTML = `
      <div class="rec-item__num">#${String(i+1).padStart(2,"0")}</div>
      <div class="rec-item__content">
        <div class="rec-item__issue">${escHtml(rec.issue || "")}</div>
        <div class="rec-item__fix">${escHtml(rec.fix || "")}</div>
      </div>
      <div class="rec-item__cat">${escHtml(rec.category || "")}
        <span class="severity-badge ${rec.severity}" style="margin-left:6px">${rec.severity}</span>
      </div>`;
    list.appendChild(item);
  });
}

// ── New scan / Export ─────────────────────────────────────────────────────────
newScanBtn.addEventListener("click", () => {
  hideAll();
  urlInput.value = "";
  urlInput.focus();
  setStatus("ready", "READY");
  currentScanId = null;
});

exportPdfBtn.addEventListener("click", () => {
  if (!currentScanId) return;
  window.open(`${API_BASE}/report/${currentScanId}?format=pdf`, "_blank");
});

// ── History ───────────────────────────────────────────────────────────────────
refreshHistoryBtn.addEventListener("click", loadHistory);

async function loadHistory() {
  const list = document.getElementById("historyList");
  list.innerHTML = `<p class="empty-state">Loading…</p>`;
  try {
    const res  = await fetch(`${API_BASE}/history`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderHistory(data.data || []);
  } catch (e) {
    list.innerHTML = `<p class="empty-state" style="color:var(--high)">Failed to load history: ${e.message}</p>`;
  }
}

function renderHistory(scans) {
  const list = document.getElementById("historyList");
  if (scans.length === 0) {
    list.innerHTML = `<p class="empty-state">No scans yet.</p>`;
    return;
  }

  list.innerHTML = "";
  scans.forEach(scan => {
    const item = document.createElement("div");
    item.className = "history-item";
    const level     = scan.risk_level || "Unknown";
    const riskClass = { Low: "ok-tag", Medium: "warn-tag", High: "bad-tag" }[level] || "";
    item.innerHTML = `
      <div class="history-item__url">${escHtml(scan.url)}</div>
      <div class="history-item__meta">
        <span class="${riskClass}">${level} (${scan.risk_score || 0}/100)</span>
        <span>${scan.created_at ? new Date(scan.created_at).toLocaleString() : ""}</span>
      </div>
      <div class="history-item__actions">
        <button class="view-btn" data-id="${scan.id}">VIEW</button>
        <button class="del-btn"  data-id="${scan.id}">✕</button>
      </div>`;
    list.appendChild(item);
  });

  // Wire up buttons
  list.querySelectorAll(".del-btn").forEach(btn => {
    btn.addEventListener("click", async e => {
      e.stopPropagation();
      const id = btn.dataset.id;
      try {
        const res = await fetch(`${API_BASE}/delete/${id}`, { method: "DELETE" });
        if (res.ok) {
          loadHistory();
        } else {
          console.error("Failed to delete scan");
        }
      } catch (err) {
        console.error("Delete error:", err);
      }
    });
  });

  list.querySelectorAll(".view-btn").forEach(btn => {
    btn.addEventListener("click", async e => {
      e.stopPropagation();
      const id = btn.dataset.id;
      window.open(`${API_BASE}/report/${id}`, "_blank");
    });
  });
}

// ── Visibility helpers ────────────────────────────────────────────────────────
function hideAll() {
  loaderWrap.hidden  = true;
  resultsWrap.hidden = true;
  errorBox.hidden    = true;
}

function showLoader() {
  loaderWrap.removeAttribute("hidden");
}

function hideLoader() {
  loaderWrap.hidden = true;
}

function showError(msg) {
  errorBox.removeAttribute("hidden");
  errorMsg.textContent = msg;
}

function setStatus(state, text) {
  statusText.textContent = text;
  statusDot.className = `status-dot ${state}`;
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}