/**
 * dashboard.js — PhishyGuard Dashboard Controller
 * Handles tabs, scan calls, charts, history, model info, and logs.
 */

// ─── State ──────────────────────────────────────────────────────────────────
let chartDonut = null;
let chartBar   = null;
let chartLine  = null;
let allScans   = [];

// ─── Init ────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  updateClock();
  setInterval(updateClock, 1000);
  refreshAll();
});

function updateClock() {
  const el = document.getElementById("topbar-time");
  if (el) el.textContent = new Date().toLocaleTimeString();
}

// ─── Tab navigation ──────────────────────────────────────────────────────────
function setupTabs() {
  document.querySelectorAll(".nav-item[data-tab]").forEach(link => {
    link.addEventListener("click", e => {
      e.preventDefault();
      switchTab(link.dataset.tab);
    });
  });
}

function switchTab(tab) {
  document.querySelectorAll(".nav-item").forEach(l => l.classList.remove("active"));
  document.querySelectorAll(".tab-section").forEach(s => s.classList.remove("active"));

  const link = document.querySelector(`.nav-item[data-tab="${tab}"]`);
  const section = document.getElementById(`tab-${tab}`);
  if (link)    link.classList.add("active");
  if (section) section.classList.add("active");

  const titles = {
    overview: "Overview", scanner: "URL Scanner",
    history: "Scan History", analytics: "Analytics",
    model: "Model Info", logs: "Event Logs",
  };
  const titleEl = document.getElementById("page-title");
  if (titleEl) titleEl.textContent = titles[tab] || tab;

  // Lazy-load per tab
  if (tab === "history")   loadHistory();
  if (tab === "analytics") loadAnalytics();
  if (tab === "model")     loadModelInfo();
  if (tab === "logs")      loadLogs();
}

// ─── Refresh all ─────────────────────────────────────────────────────────────
async function refreshAll() {
  await Promise.allSettled([loadStats(), loadRecentOverview()]);
}

// ─── Statistics ───────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res  = await fetch("/api/stats");
    const data = await res.json();
    if (!data.success) return;

    const s = data.stats;
    setText("stat-total", s.total_scans);
    setText("stat-phish", s.phishing_count);
    setText("stat-legit",  s.legit_count);
    setText("stat-today",  s.today_count);
    setText("stat-rate",   s.detection_rate + "%");

    renderDonutChart(s.phishing_count, s.legit_count);
    renderBarChart(s.daily_breakdown || []);
  } catch (e) { console.warn("Stats load failed", e); }
}

// ─── Recent scans (overview tab) ─────────────────────────────────────────────
async function loadRecentOverview() {
  try {
    const res  = await fetch("/api/recent?limit=8");
    const data = await res.json();
    if (!data.success) return;

    const container = document.getElementById("overview-recent");
    if (!container) return;
    container.innerHTML = buildScanTable(data.scans, 8);
  } catch {}
}

// ─── URL Scanner ──────────────────────────────────────────────────────────────
function setUrl(url) {
  const input = document.getElementById("scan-url");
  if (input) input.value = url;
}

async function runScan() {
  const input  = document.getElementById("scan-url");
  const btn    = document.getElementById("scan-btn");
  const url    = (input?.value || "").trim();
  if (!url) { input?.focus(); return; }

  btn.textContent = "Scanning…";
  btn.disabled    = true;

  document.getElementById("result-placeholder").classList.remove("hidden");
  document.getElementById("scan-result").classList.add("hidden");

  try {
    const runThreatIntel = document.getElementById("threat-intel-toggle")?.checked || false;

    const res  = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, threat_intel: runThreatIntel }),
    });
    const data = await res.json();

    if (data.success) {
      displayScanResult(data);
    } else {
      alert("Error: " + data.error);
    }
  } catch (e) {
    alert("Network error. Is the Flask server running?");
  }

  btn.textContent = "Scan URL";
  btn.disabled    = false;
}

function displayScanResult(data) {
  document.getElementById("result-placeholder").classList.add("hidden");
  const panel = document.getElementById("scan-result");
  panel.classList.remove("hidden");

  const isPhish = data.verdict === "phishing";
  const risk    = data.risk;

  // Banner
  const banner = document.getElementById("verdict-banner");
  banner.className = `verdict-banner ${data.verdict}`;
  document.getElementById("v-icon").textContent  = isPhish ? "🚨" : "✅";
  document.getElementById("v-label").textContent = isPhish ? "PHISHING DETECTED" : "LEGITIMATE URL";
  document.getElementById("v-url").textContent   = data.url;

  // Risk bar
  const bar   = document.getElementById("risk-bar");
  const score = risk.score;
  bar.style.width      = score + "%";
  bar.style.background = isPhish ? "#ef4444" : score > 45 ? "#f59e0b" : "#22c55e";

  document.getElementById("risk-score-num").textContent = score;
  document.getElementById("risk-conf").textContent      = `Confidence: ${data.confidence}%`;

  const badge = document.getElementById("risk-level-badge");
  badge.textContent  = risk.level;
  badge.className    = `risk-badge risk-${risk.level}`;

  // Probability bars
  const pp = data.probabilities.phishing;
  const lp = data.probabilities.legitimate;
  document.getElementById("prob-phish-bar").style.width  = pp + "%";
  document.getElementById("prob-legit-bar").style.width  = lp + "%";
  document.getElementById("prob-phish-pct").textContent  = pp + "%";
  document.getElementById("prob-legit-pct").textContent  = lp + "%";

  // Feature flags
  const flags = document.getElementById("feature-flags");
  const f     = data.features || {};
  const checks = [
    { key: "is_https",          label: "HTTPS",            ok: !!f.is_https },
    { key: "has_ip",            label: "IP Address",       ok: !f.has_ip },
    { key: "has_phish_keyword", label: "Phish Keywords",   ok: !f.has_phish_keyword },
    { key: "suspicious_tld",    label: "Suspicious TLD",   ok: !f.suspicious_tld },
    { key: "is_shortened",      label: "URL Shortener",    ok: !f.is_shortened },
    { key: "hyphen_in_domain",  label: "Hyphens in Domain",ok: !f.hyphen_in_domain },
    { key: "subdomain_count",   label: `Subdomains: ${f.subdomain_count ?? 0}`,
      ok: (f.subdomain_count ?? 0) <= 2, info: true },
    { key: "url_length",        label: `URL Len: ${f.url_length ?? 0}`,
      ok: (f.url_length ?? 0) < 100, info: true },
  ];
  flags.innerHTML = checks.map(c => {
    const cls = c.info ? "flag-info" : (c.ok ? "flag-ok" : "flag-warn");
    const icon = c.info ? "ℹ️" : (c.ok ? "✓" : "⚠");
    return `<span class="flag ${cls}">${icon} ${c.label}</span>`;
  }).join("");
}

// ─── History tab ─────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const res  = await fetch("/api/recent?limit=100");
    const data = await res.json();
    if (!data.success) return;
    allScans = data.scans;
    renderHistoryTable(allScans);
  } catch {}
}

function filterHistory() {
  const q = (document.getElementById("history-search")?.value || "").toLowerCase();
  const filtered = allScans.filter(s => s.url.toLowerCase().includes(q));
  renderHistoryTable(filtered);
}

function renderHistoryTable(scans) {
  const tbody = document.getElementById("history-tbody");
  if (!tbody) return;
  tbody.innerHTML = scans.map(s => `
    <tr>
      <td>${s.id}</td>
      <td title="${escHtml(s.url)}">${escHtml(s.url.substring(0, 60))}${s.url.length > 60 ? "…" : ""}</td>
      <td>${verdictBadge(s.verdict)}</td>
      <td>${riskBar(s.risk_score)}</td>
      <td>${s.confidence?.toFixed(1) ?? "—"}%</td>
      <td>${fmtDate(s.scanned_at)}</td>
    </tr>`
  ).join("") || `<tr><td colspan="6" style="text-align:center;color:var(--text3);padding:24px">No scans yet</td></tr>`;
}

// ─── Analytics tab ────────────────────────────────────────────────────────────
async function loadAnalytics() {
  try {
    const res  = await fetch("/api/stats");
    const data = await res.json();
    if (!data.success) return;

    renderLineChart(data.stats.daily_breakdown || []);

    const tbody = document.getElementById("top-threats-body");
    if (tbody) {
      const threats = data.stats.top_threats || [];
      tbody.innerHTML = threats.map(t => `
        <tr>
          <td title="${escHtml(t.url)}">${escHtml(t.url.substring(0, 70))}${t.url.length > 70 ? "…" : ""}</td>
          <td>${riskBar(t.risk_score)}</td>
          <td>${fmtDate(t.scanned_at)}</td>
        </tr>`
      ).join("") || `<tr><td colspan="3" style="text-align:center;color:var(--text3);padding:20px">No threats recorded yet</td></tr>`;
    }
  } catch {}
}

// ─── Model info tab ───────────────────────────────────────────────────────────
async function loadModelInfo() {
  const grid = document.getElementById("model-info-grid");
  if (!grid) return;
  try {
    const res  = await fetch("/api/model/info");
    const data = await res.json();

    if (!data.success || !data.loaded) {
      grid.innerHTML = `<div class="info-placeholder">⚠️ Model not loaded.
        Run <code>python model_training.py</code> then restart the server.</div>`;
      return;
    }

    const m = data.metrics || {};
    grid.innerHTML = `
      ${metricCard("Accuracy",  (m.accuracy  || "—") + "%", "m-green")}
      ${metricCard("Precision", (m.precision || "—") + "%", "m-green")}
      ${metricCard("Recall",    (m.recall    || "—") + "%", "m-blue")}
      ${metricCard("F1 Score",  (m.f1_score  || "—") + "%", "m-blue")}
      ${metricCard("AUC-ROC",   (m.auc_roc   || "—") + "%", "m-amber")}
      ${metricCard("Features",  data.features || "—", "m-blue")}
      ${metricCard("Train Samples", m.train_samples || "—", "")}
      ${metricCard("Test Samples",  m.test_samples  || "—", "")}
      ${featImportanceCard(m.top_features || [])}
    `;
  } catch {
    grid.innerHTML = `<div class="info-placeholder">Failed to load model info.</div>`;
  }
}

function metricCard(label, value, cls) {
  return `<div class="metric-card">
    <div class="m-label">${label}</div>
    <div class="m-value ${cls}">${value}</div>
  </div>`;
}

function featImportanceCard(features) {
  if (!features.length) return "";
  const maxImp = features[0]?.importance || 1;
  return `<div class="feat-imp-row">
    <h4>Top 10 Feature Importances</h4>
    ${features.map(f => `
      <div class="feat-imp-item">
        <div class="feat-imp-label">
          <span>${f.name}</span>
          <span>${(f.importance * 100).toFixed(1)}%</span>
        </div>
        <div class="feat-imp-track">
          <div class="feat-imp-fill" style="width:${(f.importance / maxImp * 100).toFixed(1)}%"></div>
        </div>
      </div>`).join("")}
  </div>`;
}

// ─── Logs tab ─────────────────────────────────────────────────────────────────
async function loadLogs() {
  const container = document.getElementById("log-container");
  if (!container) return;
  try {
    const res  = await fetch("/api/logs?limit=100");
    const data = await res.json();
    if (!data.success) return;
    container.innerHTML = data.logs.map(l => `
      <div class="log-line">
        <span class="log-time">${fmtDate(l.logged_at)}</span>
        <span class="log-type log-${l.event_type}">${l.event_type.toUpperCase()}</span>
        <span class="log-msg">${escHtml(l.message || "")}</span>
      </div>`
    ).join("") || `<div style="padding:20px;color:var(--text3)">No logs yet.</div>`;
  } catch {}
}

// ─── Charts ───────────────────────────────────────────────────────────────────
function renderDonutChart(phishing, legit) {
  const ctx = document.getElementById("chart-donut")?.getContext("2d");
  if (!ctx) return;
  if (chartDonut) chartDonut.destroy();

  chartDonut = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Phishing", "Legitimate"],
      datasets: [{
        data: [phishing || 0, legit || 0],
        backgroundColor: ["#ef4444", "#22c55e"],
        borderWidth: 0,
        hoverOffset: 4,
      }],
    },
    options: {
      responsive: true,
      cutout: "68%",
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#94a3b8", font: { size: 12 }, padding: 16 },
        },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed}`
          }
        }
      },
    },
  });
}

function renderBarChart(daily) {
  const ctx = document.getElementById("chart-bar")?.getContext("2d");
  if (!ctx) return;
  if (chartBar) chartBar.destroy();

  const labels = daily.map(d => d.day || d.date || "");
  const phish  = daily.map(d => d.phishing  || 0);
  const legit  = daily.map(d => d.legitimate || 0);

  chartBar = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        { label: "Phishing",   data: phish, backgroundColor: "rgba(239,68,68,.7)",  borderRadius: 4 },
        { label: "Legitimate", data: legit, backgroundColor: "rgba(34,197,94,.6)",  borderRadius: 4 },
      ],
    },
    options: {
      responsive: true,
      scales: {
        x: {
          grid:  { color: "#2a3347" },
          ticks: { color: "#64748b", font: { size: 11 } },
        },
        y: {
          grid:  { color: "#2a3347" },
          ticks: { color: "#64748b", font: { size: 11 }, precision: 0 },
          beginAtZero: true,
        },
      },
      plugins: { legend: { labels: { color: "#94a3b8", font: { size: 12 } } } },
    },
  });
}

function renderLineChart(daily) {
  const ctx = document.getElementById("chart-line")?.getContext("2d");
  if (!ctx) return;
  if (chartLine) chartLine.destroy();

  const labels = daily.map(d => d.day || "");
  const phish  = daily.map(d => d.phishing  || 0);
  const legit  = daily.map(d => d.legitimate || 0);

  chartLine = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Phishing", data: phish,
          borderColor: "#ef4444", backgroundColor: "rgba(239,68,68,.12)",
          fill: true, tension: 0.4, pointRadius: 4,
        },
        {
          label: "Legitimate", data: legit,
          borderColor: "#22c55e", backgroundColor: "rgba(34,197,94,.1)",
          fill: true, tension: 0.4, pointRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      scales: {
        x: {
          grid:  { color: "#2a3347" },
          ticks: { color: "#64748b", font: { size: 11 } },
        },
        y: {
          grid:  { color: "#2a3347" },
          ticks: { color: "#64748b", font: { size: 11 }, precision: 0 },
          beginAtZero: true,
        },
      },
      plugins: { legend: { labels: { color: "#94a3b8", font: { size: 12 } } } },
    },
  });
}

// ─── Overview recent scans table ─────────────────────────────────────────────
function buildScanTable(scans, limit = 8) {
  if (!scans || !scans.length) {
    return `<p style="color:var(--text3);padding:12px">No scans yet.</p>`;
  }
  return `<table class="data-table">
    <thead><tr>
      <th>#</th><th>URL</th><th>Verdict</th>
      <th>Risk Score</th><th>Scanned At</th>
    </tr></thead>
    <tbody>
      ${scans.slice(0, limit).map(s => `<tr>
        <td>${s.id}</td>
        <td title="${escHtml(s.url)}">${escHtml(s.url.substring(0, 55))}${s.url.length > 55 ? "…" : ""}</td>
        <td>${verdictBadge(s.verdict)}</td>
        <td>${riskBar(s.risk_score)}</td>
        <td>${fmtDate(s.scanned_at)}</td>
      </tr>`).join("")}
    </tbody>
  </table>`;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function verdictBadge(verdict) {
  if (verdict === "phishing")   return `<span class="badge badge-danger">Phishing</span>`;
  if (verdict === "legitimate") return `<span class="badge badge-success">Legitimate</span>`;
  return `<span class="badge badge-warning">${verdict}</span>`;
}

function riskBar(score) {
  const s   = parseFloat(score) || 0;
  const col = s >= 75 ? "#ef4444" : s >= 45 ? "#f59e0b" : "#22c55e";
  return `<div style="display:flex;align-items:center;gap:6px">
    <div style="width:60px;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden">
      <div style="width:${s}%;height:100%;background:${col};border-radius:3px"></div>
    </div>
    <span style="font-size:12px;color:var(--text2)">${s.toFixed(1)}</span>
  </div>`;
}

function fmtDate(dt) {
  if (!dt) return "—";
  try {
    return new Date(dt).toLocaleString("en-US", {
      month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return dt; }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// Keyboard shortcut: Enter on scanner input
document.addEventListener("keydown", e => {
  if (e.key === "Enter") {
    const active = document.querySelector(".tab-section.active");
    if (active?.id === "tab-scanner") runScan();
  }
});

// ─── Threat Intel & WHOIS display (v2 additions) ─────────────────────────────

function displayThreatIntel(data) {
  const tiSection = document.getElementById("threat-intel-section");
  const tiVt      = document.getElementById("ti-vt");
  const tiGsb     = document.getElementById("ti-gsb");
  if (!data.threat_intel || !tiSection) return;

  tiSection.classList.remove("hidden");
  const ti = data.threat_intel;

  // VirusTotal
  const vt = ti.virustotal || {};
  if (vt.available) {
    const cls = vt.vt_verdict === "malicious"  ? "badge-danger"  :
                vt.vt_verdict === "suspicious" ? "badge-warning" : "badge-success";
    tiVt.innerHTML = `
      <span class="ti-label">VirusTotal</span>
      <span class="badge ${cls}">${vt.vt_verdict.toUpperCase()}</span>
      <span class="ti-detail">${vt.malicious} malicious / ${vt.total_engines} engines</span>
      ${vt.permalink ? `<a href="${escHtml(vt.permalink)}" target="_blank" class="ti-link">View report →</a>` : ""}
    `;
  } else {
    tiVt.innerHTML = `<span class="ti-label">VirusTotal</span><span class="ti-na">${escHtml(vt.error || "Not available")}</span>`;
  }

  // Google Safe Browsing
  const gsb = ti.safe_browsing || {};
  if (gsb.available) {
    const cls = gsb.is_threat ? "badge-danger" : "badge-success";
    const lbl = gsb.is_threat ? "THREAT DETECTED" : "CLEAN";
    const types = (gsb.threat_types || []).join(", ") || "";
    tiGsb.innerHTML = `
      <span class="ti-label">Safe Browsing</span>
      <span class="badge ${cls}">${lbl}</span>
      ${types ? `<span class="ti-detail">${escHtml(types)}</span>` : ""}
    `;
  } else {
    tiGsb.innerHTML = `<span class="ti-label">Safe Browsing</span><span class="ti-na">${escHtml(gsb.error || "Not available")}</span>`;
  }
}

function displayWhoisFlags(features) {
  const section = document.getElementById("whois-section");
  const flags   = document.getElementById("whois-flags");
  if (!section || !flags) return;

  const f = features || {};
  const whoisPresent = "domain_age_days" in f || "dns_resolves" in f;
  if (!whoisPresent) return;

  section.classList.remove("hidden");

  const age = f.domain_age_days;
  const items = [
    {
      label: age >= 0 ? `Domain age: ${age} days` : "Domain age: unknown",
      ok:    age < 0 || age >= 180,
      info:  true,
    },
    { label: "New domain (<180d)", ok: !f.is_new_domain,    info: false },
    { label: "DNS resolves",       ok: !!f.dns_resolves,    info: false },
    { label: "WHOIS available",    ok: !!f.whois_available, info: true  },
    { label: "Privacy guard",      ok: !f.has_privacy_guard,info: false },
  ];

  flags.innerHTML = items.map(c => {
    const cls  = c.info ? "flag-info" : (c.ok ? "flag-ok" : "flag-warn");
    const icon = c.info ? "ℹ️" : (c.ok ? "✓" : "⚠");
    return `<span class="flag ${cls}">${icon} ${c.label}</span>`;
  }).join("");
}

// Patch the existing displayScanResult to also render threat intel + WHOIS
const _origDisplay = displayScanResult;
displayScanResult = function(data) {
  _origDisplay(data);
  displayThreatIntel(data);
  displayWhoisFlags(data.features);
};
