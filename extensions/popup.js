// ---------- Config ----------
let baseURL = "http://127.0.0.1:5000";
const api = typeof browser !== "undefined" ? browser : chrome;

// Elements
const lastScannedEl = document.getElementById("last-scanned");
const totalText = document.getElementById("total-text");
const segHigh = document.getElementById("seg-high");
const segMed  = document.getElementById("seg-med");
const segLow  = document.getElementById("seg-low");
const countHigh = document.getElementById("count-high");
const countMed  = document.getElementById("count-med");
const countLow  = document.getElementById("count-low");
const serverChip = document.getElementById("server-chip");
const modeBadge  = document.getElementById("mode-badge");
const strictStrip = document.getElementById("strict-strip");
const killedEl   = document.getElementById("killed");
const modeCard   = document.getElementById("mode-card");
const uptimeMini = document.getElementById("uptime-mini");
const activeMini = document.getElementById("active-mini");

// Bottom toggles and actions
const modeToggle   = document.getElementById("modeToggle");
const themeToggle  = document.getElementById("themeToggle");
document.getElementById("dashboardBtn").addEventListener("click", () => api.tabs.create({ url: baseURL + "/" }));
document.getElementById("refreshBtn").addEventListener("click", hydrate);

// Manage sheet
const panel = document.getElementById("panel");
document.getElementById("manageBtn").addEventListener("click", () => panel.classList.remove("hidden"));
document.getElementById("closePanel").addEventListener("click", () => panel.classList.add("hidden"));
document.getElementById("panelRefresh").addEventListener("click", hydrate);
document.getElementById("gotoDash").addEventListener("click", () => api.tabs.create({ url: baseURL + "/" }));

// Mirror panel switches with footer switches
const uiModeToggle  = document.getElementById("uiModeToggle");
const uiThemeToggle = document.getElementById("uiThemeToggle");

// ---------- Helpers ----------
function timeAgo(iso) {
  if (!iso) return "—";
  const then = new Date(iso);
  const s = Math.floor((Date.now() - then.getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function setServerChip(active) {
  serverChip.textContent = active ? "Active" : "Stopped";
  serverChip.classList.toggle("chip-on", active);
  serverChip.classList.toggle("chip-off", !active);
  activeMini.textContent = active ? "Active" : "Inactive";
}

function setGradientsForMode(mode) {
  // prettier ring gradient based on mode
  const grad = document.querySelector("#gradHigh");
  if (!grad) return;
  const stops = grad.querySelectorAll("stop");
  if (mode === "strict") {
    stops[0].setAttribute("stop-color", "#ff7a7a");
    stops[1].setAttribute("stop-color", "#ff3d3d");
  } else {
    stops[0].setAttribute("stop-color", "#ff8a00");
    stops[1].setAttribute("stop-color", "#ff3b3b");
  }
}

function drawRing(high, med, low) {
  const total = Math.max(high + med + low, 1);
  const c = 2 * Math.PI * 46;
  const pct = n => (n / total) * c;
  const gap = 4;

  const vH = Math.max(0, pct(high) - gap);
  const vM = Math.max(0, pct(med)  - gap);
  const vL = Math.max(0, pct(low)  - gap);

  segHigh.style.strokeDasharray = `${vH} ${c}`;
  segMed .style.strokeDasharray = `${vM} ${c}`;
  segLow .style.strokeDasharray = `${vL} ${c}`;

  segHigh.style.strokeDashoffset = 0;
  segMed .style.strokeDashoffset = -(vH + gap);
  segLow .style.strokeDashoffset = -(vH + vM + 2*gap);

  totalText.textContent = high + med + low;
}

// ---------- Hydrate from backend ----------
async function hydrate() {
  try {
    const r = await fetch(baseURL + "/api/threats", { cache: "no-store" });
    if (!r.ok) throw new Error("API error");
    const payload = await r.json();

    const summary = payload?.data?.summary || {};
    const status  = payload?.data?.status  || {};

    const high = summary.high   || 0;
    const med  = summary.medium || 0;
    const low  = summary.low    || 0;

    countHigh.textContent = high;
    countMed .textContent = med;
    countLow .textContent = low;
    drawRing(high, med, low);

    lastScannedEl.textContent = timeAgo(status.last_scan);
    setServerChip(Boolean(status.active));

    // backend mode drives badge + card tint
    const backendMode = (status.mode || "strict").toString();
    const modeLabel = backendMode.charAt(0).toUpperCase() + backendMode.slice(1);
    modeBadge.textContent = modeLabel;
    modeCard.classList.remove("strict","lenient");
    modeCard.classList.add(backendMode === "strict" ? "strict" : "lenient");
    setGradientsForMode(backendMode);

    // strict strip
    if (backendMode === "strict") {
      killedEl.textContent = summary.neutralized || 0;
      strictStrip.classList.remove("strip-hidden");
    } else {
      strictStrip.classList.add("strip-hidden");
    }

    // uptime mini
    if (status.uptime_seconds != null) {
      const s = Number(status.uptime_seconds);
      const h = Math.floor(s/3600), m = Math.floor((s%3600)/60);
      uptimeMini.textContent = `${h}h ${m}m`;
    } else {
      uptimeMini.textContent = "—";
    }
  } catch (e) {
    setServerChip(false);
    lastScannedEl.textContent = "unavailable";
    drawRing(0,0,0);
    countHigh.textContent = "—";
    countMed .textContent = "—";
    countLow .textContent = "—";
    strictStrip.classList.add("strip-hidden");
    uptimeMini.textContent = "—";
  }
}

// ---------- UI-only toggles (fixed) ----------
function applyTheme(theme){
  document.documentElement.classList.toggle("light", theme === "light");
}
function applyUIMode(pref){
  // purely visual: tints card + badge text hint (without touching backend)
  modeCard.classList.remove("strict","lenient");
  modeCard.classList.add(pref === "strict" ? "strict" : "lenient");
}

async function loadPrefs() {
  const { baseURL: saved, popupTheme, popupModePref } = await api.storage.local.get(["baseURL","popupTheme","popupModePref"]);
  if (saved) baseURL = saved;

  // theme
  const theme = popupTheme || "dark";
  themeToggle.checked = theme === "light";
  uiThemeToggle.checked = theme === "light";
  applyTheme(theme);

  // visual mode label
  const pref = popupModePref || "lenient";
  const checked = pref === "strict";
  modeToggle.checked = checked;
  uiModeToggle.checked = checked;
  applyUIMode(pref);

  await hydrate();
}

// hook up both sets of switches
async function saveThemeFrom(el){
  const theme = el.checked ? "light" : "dark";
  applyTheme(theme);
  await api.storage.local.set({ popupTheme: theme });
}
async function saveModePrefFrom(el){
  const pref = el.checked ? "strict" : "lenient";
  applyUIMode(pref);
  await api.storage.local.set({ popupModePref: pref });
}

themeToggle.addEventListener("change", () => saveThemeFrom(themeToggle));
modeToggle .addEventListener("change", () => saveModePrefFrom(modeToggle));

uiThemeToggle.addEventListener("change", () => {
  themeToggle.checked = uiThemeToggle.checked;
  saveThemeFrom(uiThemeToggle);
});
uiModeToggle.addEventListener("change", () => {
  modeToggle.checked = uiModeToggle.checked;
  saveModePrefFrom(uiModeToggle);
});

// boot
loadPrefs();

