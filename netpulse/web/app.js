/* NetPulse frontend v2 - vanilla JS */
"use strict";

window.__npErrors = [];
window.addEventListener("error", (e) => {
  try {
    window.__npErrors.push(String(e.message || e) + " @" + (e.filename || "").split("/").pop() +
      ":" + (e.lineno || "?"));
    let d = document.getElementById("np-err-dump");
    if (!d && document.body) {
      d = document.createElement("div");
      d.id = "np-err-dump";
      d.style.display = "none";
      document.body.appendChild(d);
    }
    if (d) d.textContent = JSON.stringify(window.__npErrors);
    console.error("[np]", e.message);
  } catch (_) {}
});

const $ = (id) => document.getElementById(id);

const Auth = {
  get() { return localStorage.getItem("np-token") || ""; },
  set(t) { localStorage.setItem("np-token", t); },
  suffix() { const t = this.get(); return t ? `?token=${encodeURIComponent(t)}` : ""; },
};

async function apiGet(path) {
  const r = await fetch("/api/" + path + Auth.suffix(), { headers: { "X-Auth": Auth.get() } });
  if (r.status === 401) throw new UnauthorizedError();
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}
async function apiPost(path, body = {}) {
  const r = await fetch("/api/" + path + Auth.suffix(), {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Auth": Auth.get() },
    body: JSON.stringify(body),
  });
  if (r.status === 401) throw new UnauthorizedError();
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}
class UnauthorizedError extends Error {}

function toast(msg, isError = false) {
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " error" : "");
  el.textContent = msg;
  $("toast-wrap").appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtNum(n) {
  if (n == null || isNaN(n)) return "0";
  return (+n).toLocaleString("ru-RU", { maximumFractionDigits: 1 });
}
function fmtMB(mb) { return mb >= 1024 ? (mb / 1024).toFixed(2) + " GB" : mb.toFixed(1); }
function fmtUptime(sec) {
  if (sec < 60) return sec + "с";
  if (sec < 3600) return Math.floor(sec / 60) + "м " + (sec % 60) + "с";
  return Math.floor(sec / 3600) + "ч " + Math.floor((sec % 3600) / 60) + "м";
}
function timeAgo(ts) {
  const d = Math.max(0, Date.now() / 1000 - ts);
  if (d < 60) return Math.floor(d) + "с назад";
  if (d < 3600) return Math.floor(d / 60) + " мин назад";
  return new Date(ts * 1000).toLocaleTimeString("ru-RU");
}

/* ================= графики ================= */

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}
function prepCanvas(cv) {
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth || cv.parentElement.clientWidth || 600;
  const h = parseInt(cv.getAttribute("height")) || 160;
  if (cv.width !== w * dpr || cv.height !== h * dpr) {
    cv.width = w * dpr; cv.height = h * dpr;
    cv.style.height = h + "px";
  }
  const ctx = cv.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h };
}
function drawGrid(ctx, w, h, rows = 4) {
  ctx.strokeStyle = cssVar("--border-soft");
  ctx.lineWidth = 1;
  for (let i = 1; i <= rows; i++) {
    const y = (h / (rows + 1)) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
}
function areaSeries(ctx, w, h, values, color, maxOverride = null) {
  if (!values.length) return;
  const max = Math.max(maxOverride || 0, ...values.map(v => v ?? 0), 1) * 1.15;
  const step = w / Math.max(values.length - 1, 1);
  const pts = values.map((v, i) => [i * step, h - ((v ?? 0) / max) * h * 0.92]);
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, color + "55"); grad.addColorStop(1, color + "00");
  ctx.beginPath(); ctx.moveTo(0, h);
  pts.forEach(([x, y]) => ctx.lineTo(x, y));
  ctx.lineTo(pts[pts.length - 1][0], h); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();
  ctx.beginPath();
  pts.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
  ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.stroke();
  const [lx, ly] = pts[pts.length - 1];
  ctx.beginPath(); ctx.arc(lx, ly, 3.5, 0, Math.PI * 2);
  ctx.fillStyle = color; ctx.fill();
}
function drawSpark(cvId, values, color) {
  const cv = $(cvId);
  if (!cv || !values.length) return;
  const { ctx, w, h } = prepCanvas(cv);
  ctx.clearRect(0, 0, w, h);
  areaSeries(ctx, w, h, values.slice(-60), color);
}
function drawMainChart(data, forecast) {
  const cv = $("chart-main"); if (!cv) return;
  const { ctx, w, h } = prepCanvas(cv);
  ctx.clearRect(0, 0, w, h);
  drawGrid(ctx, w, h, 4);
  const downs = data.map(p => p.down_kbps);
  const ups = data.map(p => p.up_kbps);
  const commonMax = Math.max(...downs, ...ups, ...(forecast ? [forecast] : []), 10) * 1.15;
  areaSeries(ctx, w, h, downs, cssVar("--cyan"), commonMax);
  areaSeries(ctx, w, h, ups, cssVar("--violet"), commonMax);
  if (forecast != null && data.length > 5) {
    const lastX = (data.length - 1) / Math.max(data.length - 1, 1) * w;
    const step = w / Math.max(data.length - 1, 1);
    ctx.beginPath();
    ctx.setLineDash([6, 5]);
    ctx.moveTo(lastX, h - (data[data.length - 1].down_kbps / commonMax) * h * 0.92);
    ctx.lineTo(Math.min(w, lastX + step * 30), h - (forecast / commonMax) * h * 0.92);
    ctx.strokeStyle = cssVar("--amber"); ctx.stroke();
    ctx.setLineDash([]);
  }
}
function drawGauge(score, color) {
  const cv = $("gauge"); if (!cv) return;
  const dpr = window.devicePixelRatio || 1;
  cv.width = 120 * dpr; cv.height = 120 * dpr;
  const ctx = cv.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const cx = 60, cy = 62, r = 46;
  const start = Math.PI * 0.75, end = Math.PI * 2.25;
  ctx.lineWidth = 11; ctx.lineCap = "round";
  ctx.beginPath(); ctx.arc(cx, cy, r, start, end);
  ctx.strokeStyle = cssVar("--panel2"); ctx.stroke();
  ctx.beginPath(); ctx.arc(cx, cy, r, start, start + (end - start) * (score / 100));
  ctx.strokeStyle = color; ctx.stroke();
}
function drawHistChart(cvId, seriesList) {
  const cv = $(cvId); if (!cv) return;
  const { ctx, w, h } = prepCanvas(cv);
  ctx.clearRect(0, 0, w, h);
  drawGrid(ctx, w, h, 4);
  const colors = ["--cyan", "--violet"];
  seriesList.forEach((s, idx) => {
    if (!s.values.length) return;
    const step = w / Math.max(s.values.length - 1, 1);
    const max = Math.max(...s.values, 1) * 1.15;
    ctx.beginPath();
    s.values.forEach((v, i) => {
      const x = i * step, y = h - (v / max) * h * 0.9;
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.strokeStyle = cssVar(colors[idx]); ctx.lineWidth = 2; ctx.stroke();
  });
}
function sparklineSVG(values, color) {
  const vals = values.filter(v => v != null);
  if (vals.length < 2) return "";
  const w = 110, hh = 22;
  const max = Math.max(...vals, 1);
  const pts = values.slice(-60).map((v, i, arr) =>
    `${(i / Math.max(arr.length - 1, 1)) * w},${hh - ((v ?? 0) / max) * hh}`).join(" ");
  return `<svg width="${w}" height="${hh}" style="display:block"><polyline points="${pts}"
    fill="none" stroke="${color}" stroke-width="1.6"/></svg>`;
}

/* ================= UI ================= */

const VIEW_TITLES = {
  dashboard: "Дашборд", journal: "Журнал работ", apps: "Приложения и сеть",
  traffic: "Соединения и интерфейсы", diag: "Диагностика сети",
  lan: "Локальная сеть", park: "Парк ПК", capture: "Захват пакетов",
  security: "Безопасность и IDS", ai: "AI-аналитика", alerts: "Алерты",
  history: "История", settings: "Настройки",
};

const UI = {
  currentView: "dashboard",
  stateHistory: [],
  lastAlertCount: null,
  captureOn: false,

  init() {
    document.querySelectorAll(".nav-btn").forEach(b =>
      b.addEventListener("click", () => this.switchView(b.dataset.view)));
    $("theme-toggle").addEventListener("change", e => {
      const dark = e.target.checked;
      document.documentElement.dataset.theme = dark ? "dark" : "light";
      localStorage.setItem("np-theme", dark ? "dark" : "light");
    });
    const savedTheme = localStorage.getItem("np-theme") || "dark";
    document.documentElement.dataset.theme = savedTheme;
    $("theme-toggle").checked = savedTheme === "dark";

    $("show-listening").addEventListener("change", () => this.refreshConns());
    this.switchView(this.hashView() || "dashboard");
    this.loadDashPlatform();
    setInterval(() => this.loadDashPlatform(), 60000);
    window.addEventListener("hashchange", () => {
      const v = this.hashView();
      if (v && v !== this.currentView) this.switchView(v);
    });
    setInterval(() => { $("clock").textContent = new Date().toLocaleTimeString("ru-RU"); }, 1000);

    this.startStream();

    setInterval(() => {
      const v = this.currentView;
      if (v === "apps") { this.loadApps(); this.loadNewConns(); }
      if (v === "traffic") { this.refreshInterfaces(); this.refreshConns(); }
      if (v === "capture" && this.captureOn) this.captureRefresh(false);
      if (v === "security") this.loadIds();
      if (v === "alerts") this.loadAlerts();
      if (v === "diag" && MtrActive) this.mtrPoll(true);
    }, 4000);

    if ("Notification" in window && Notification.permission === "default")
      setTimeout(() => Notification.requestPermission().catch(() => {}), 5000);
  },

  hashView() {
    const v = decodeURIComponent(location.hash.replace(/^#\/?/, ""));
    return VIEW_TITLES[v] ? v : "";
  },

  switchView(view) {
    if (!VIEW_TITLES[view]) view = "dashboard";
    this.currentView = view;
    try { history.replaceState(null, "", "#" + view); } catch (e) {}
    document.querySelectorAll(".nav-btn").forEach(b =>
      b.classList.toggle("active", b.dataset.view === view));
    document.querySelectorAll(".view").forEach(v =>
      v.classList.toggle("active", v.id === "view-" + view));
    $("view-title").textContent = VIEW_TITLES[view] || view;
    $("sidebar").classList.remove("open");

    if (view === "traffic") { this.refreshInterfaces(); this.refreshConns(); }
    if (view === "apps") { this.loadApps(); this.loadNewConns(); }
    if (view === "security") { this.loadIds(); this.fwList(); }
    if (view === "ai") this.loadAI();
    if (view === "alerts") this.loadAlerts();
    if (view === "history") this.loadHistory();
    if (view === "settings") this.loadSettings();
    if (view === "journal") this.loadJournal();
    if (view === "park") this.loadPark();
  },

  /* ---------- живой поток состояния ---------- */
  startStream() {
    try {
      const es = new EventSource("/api/stream" + Auth.suffix());
      es.onmessage = (e) => {
        if (!e.data || e.data === "ping") return;
        try {
          const snap = JSON.parse(e.data);
          this.renderState(snap);
          $("login-overlay").classList.add("hidden");
        } catch (err) {}
      };
      es.onerror = () => {
        es.close();
        setTimeout(() => this.startStream(), 3000);
        this.fallbackPoll();
      };
      return;
    } catch (err) {
      this.fallbackPoll();
    }
  },
  fallbackStarted: false,
  fallbackPoll() {
    if (this.fallbackStarted) return;
    this.fallbackStarted = true;
    const loop = async () => {
      try {
        const snap = await apiGet("state");
        this.renderState(snap);
      } catch (e) {
        if (e instanceof UnauthorizedError) this.showLogin();
      }
      setTimeout(loop, 1500);
    };
    loop();
  },

  showLogin() {
    $("login-overlay").classList.remove("hidden");
  },
  async login() {
    const t = $("login-token").value.trim();
    Auth.set(t);
    try {
      await apiGet("state");
      $("login-overlay").classList.add("hidden");
      $("login-error").textContent = "";
      location.reload();
    } catch (e) {
      $("login-error").textContent = "Неверный токен";
    }
  },

  /* ---------- рендер состояния ---------- */
  renderState(snap) {
    $("st-down").innerHTML = `${fmtNum(snap.down_kbps)}<span class="unit"> KB/s</span>`;
    $("st-up").innerHTML = `${fmtNum(snap.up_kbps)}<span class="unit"> KB/s</span>`;

    const pingEl = $("st-ping");
    pingEl.innerHTML =
      `${snap.ping.current != null ? fmtNum(snap.ping.current) : "—"}<span class="unit"> ms</span>`;
    pingEl.style.color =
      snap.ping.current == null ? "" :
      snap.ping.current < 60 ? cssVar("--cyan") :
      snap.ping.current < 130 ? cssVar("--amber") : cssVar("--danger");
    $("st-ping-sub").textContent =
      `джиттер ${fmtNum(snap.ping.jitter)} ms · потери ${snap.ping.loss_pct}%`;

    drawGauge(snap.quality.score, snap.quality.color);
    $("gauge-num").textContent = snap.quality.score;
    $("quality-label").textContent = snap.quality.label;
    $("quality-label").style.color = snap.quality.color;
    const qp = $("quality-pill");
    qp.querySelector(".dot").style.background = snap.quality.color;
    $("quality-text").textContent = `${snap.quality.label} · ${snap.quality.score}`;

    if (snap.system) {
      $("pill-cpu").textContent = fmtNum(snap.system.cpu) + "%";
      $("pill-mem").textContent = fmtNum(snap.system.mem_pct) + "%";
    }

    const modeNames = { real: "Live", psutil: "Net", sim: "Sim" };
    const pill = $("mode-pill");
    if (pill) {
      pill.querySelector(".dot").style.background =
        snap.mode.admin ? cssVar("--cyan") : cssVar("--accent");
      pill.innerHTML = `<span class="dot"></span><b>${modeNames[snap.mode.traffic] || ""}</b>` +
        (snap.mode.admin ? " admin" : "");
    }

    $("ss-total-down").textContent = fmtMB(snap.total_down_mb) + " MB";
    $("ss-total-up").textContent = fmtMB(snap.total_up_mb) + " MB";
    $("ss-max").textContent = fmtNum(snap.max_kbps) + " KB/s";
    $("ss-uptime").textContent = fmtUptime(snap.uptime_sec);

    if (snap.forecast) {
      $("dash-forecast").className = "kv";
      $("dash-forecast").innerHTML =
        `Через 5 минут: <b>${fmtNum(snap.forecast.predicted_kbps_5min)} KB/s</b><br>` +
        `<span class="muted">тренд ${snap.forecast.slope_kbps_per_min >= 0 ? "+" : ""}` +
        `${snap.forecast.slope_kbps_per_min} KB/s в минуту</span>`;
      $("fc-note").classList.remove("hidden");
      $("fc-note").textContent =
        `прогноз AI: ${fmtNum(snap.forecast.predicted_kbps_5min)} KB/s`;
    }

    if (snap.quota) {
      const q = snap.quota;
      let html = "";
      if (q.daily_limit_mb > 0) {
        const cls = q.daily_pct >= 100 ? "over" : q.daily_pct >= 80 ? "warn" : "";
        html += `<div>Сегодня: ${fmtMB(q.daily_used_mb)} / ${q.daily_limit_mb} MB (${q.daily_pct}%)
          <div class="quota-bar"><i class="${cls}" style="width:${Math.min(q.daily_pct, 100)}%"></i></div></div>`;
      }
      if (q.monthly_limit_gb > 0) {
        const cls = q.monthly_pct >= 100 ? "over" : q.monthly_pct >= 80 ? "warn" : "";
        html += `<div>Месяц: ${q.monthly_used_gb} / ${q.monthly_limit_gb} GB (${q.monthly_pct}%)
          <div class="quota-bar"><i class="${cls}" style="width:${Math.min(q.monthly_pct, 100)}%"></i></div></div>`;
      }
      $("dash-quota").className = html ? "quota-box" : "quota-box muted";
      $("dash-quota").innerHTML = html || "лимиты не заданы — включите в настройках";
    }

    this.stateHistory.push(snap);
    if (this.stateHistory.length > 240) this.stateHistory.shift();
    drawSpark("spark-down", this.stateHistory.map(s => s.down_kbps), cssVar("--cyan"));
    drawSpark("spark-up", this.stateHistory.map(s => s.up_kbps), cssVar("--violet"));
    if (this.currentView === "dashboard") {
      drawMainChart(this.stateHistory.slice(-180),
        snap.forecast ? snap.forecast.predicted_kbps_5min : null);
    }

    if (this.lastAlertCount !== null && snap.alerts_unread > this.lastAlertCount
        && "Notification" in window && Notification.permission === "granted") {
      try {
        new Notification("NetPulse: новый алерт", {
          body: `Непринятых алертов: ${snap.alerts_unread}`, tag: "np-alert",
        });
      } catch (e) {}
    }
    this.lastAlertCount = snap.alerts_unread;
    const badge = $("alerts-badge");
    badge.textContent = snap.alerts_unread;
    badge.classList.toggle("hidden", !snap.alerts_unread);
  },

  async loadTopProcs() { void 0; },

  /* ---------- apps ---------- */
  async loadApps() {
    try {
      const d = await apiGet("apps");
      const tb = $("apps-table").querySelector("tbody");
      tb.innerHTML = d.apps.map(a => `
        <tr>
          <td>${esc(a.name)}</td>
          <td class="mono">${a.pid}</td>
          <td>${a.conns}</td>
          <td>${a.est}</td>
          <td><b style="color:${a.io_kbps > 50 ? cssVar("--amber") : "inherit"}">${fmtNum(a.io_kbps)}</b></td>
          <td><button class="mini-btn" title="Блокировать приложение в firewall"
            onclick="UI.blockApp('${esc(a.name).replace(/'/g, '')}', ${a.pid})">
            <svg class="ic sm"><use href="#i-block"/></svg></button></td>
        </tr>`).join("") || '<tr><td colspan=6 class=muted>нет данных</td></tr>';
      const anyActive = d.apps.some(a => a.io_kbps > 10);
      $("apps-live-dot").classList.toggle("hidden", !anyActive);
    } catch (e) { if (!(e instanceof UnauthorizedError)) toast(String(e), true); else this.showLogin(); }
  },

  async blockApp(name, pid) {
    if (!confirm(`Заблокировать сетевую активность приложения "${name}" (PID ${pid})\nчерез Windows Firewall?`)) return;
    try {
      const info = await apiGet(`appexe?pid=${pid}`);
      let path = info.exe || "";
      if (!path) {
        path = prompt("Путь к exe не получен — введите вручную:");
        if (!path) return;
      }
      const res = await apiPost("fwblockapp", { pid, path });
      if (res.ok) {
        toast(`Заблокировано: ${res.path}`);
        this.fwList();
      } else {
        toast(res.error || "Не удалось (нужны права администратора)", true);
      }
    } catch (e) { toast(String(e), true); }
  },

  async loadNewConns() {
    try {
      const d = await apiGet("appnewconn");
      const feed = $("newconn-feed");
      feed.className = "feed";
      feed.innerHTML = d.events.length ? d.events.map(e => `
        <div class="feed-item ${e.suspicious ? "danger" : ""}">
          <div class="fi-head"><span class="fi-type">${esc(e.process)}</span>
            <span class="chip ${e.suspicious ? "SUSPICIOUS_CONN" : "OK"}">${e.suspicious ? "подозрит. порт" : "новое"}</span>
            <time class="time-stamp">${timeAgo(e.ts)}</time></div>
          <div class="fi-body mono">${esc(e.remote)}</div>
        </div>`).join("") : "";
    } catch (e) { void e; }
  },

  /* ---------- traffic ---------- */
  async refreshInterfaces() {
    try {
      const list = await apiGet("interfaces");
      if (!Array.isArray(list)) {
        throw new Error(list && list.error ? list.error : "формат данных интерфейсов");
      }
      const tb = $("ifaces-table").querySelector("tbody");
      tb.innerHTML = list.map(i => `
        <tr>
          <td>${esc(i.name)}</td>
          <td>${esc(i.ipv4 || "—")}</td>
          <td class="mono">${esc((i.mac || "").slice(0, 17) || "—")}</td>
          <td>${i.up ? '<span class="ok-dot"></span>активен' : '<span class="off-dot"></span>вниз'}</td>
          <td><b style="color:${cssVar("--cyan")}">${fmtNum(i.down_kbps)}</b></td>
          <td><b style="color:${cssVar("--violet")}">${fmtNum(i.up_kbps)}</b></td>
        </tr>`).join("") || '<tr><td colspan=6 class=muted>интерфейсы не найдены</td></tr>';
    } catch (e) { toast("Интерфейсы: " + e.message, true); }
  },

  async refreshConns() {
    try {
      const listen = $("show-listening").checked ? "1" : "0";
      const data = await apiGet(`connections?listening=${listen}&limit=150`);
      const tb = $("conns-table").querySelector("tbody");
      tb.innerHTML = (data.connections || []).map(c => {
        const rip = c.remote.split(":")[0];
        return `
        <tr>
          <td>${esc(c.process)}</td>
          <td>${esc(c.local)}</td>
          <td>${esc(c.remote)}</td>
          <td><span class="chip ${c.status === "ESTABLISHED" ? "HIGH" :
              c.status === "LISTEN" ? "MEDIUM" : "INFO"}">${esc(c.status)}</span></td>
          <td>${/^(\d{1,3}\.){3}\d{1,3}$/.test(rip) && rip !== "0.0.0.0" ?
            `<button class="mini-btn" title="Блокировать IP в Windows Firewall"
              onclick="UI.blockIP('${rip}')"><svg class="ic sm"><use href="#i-block"/></svg></button>` : ""}
          </td>
        </tr>`;
      }).join("") || '<tr><td colspan=5 class=muted>нет соединений</td></tr>';
    } catch (e) { toast(String(e), true); }
  },

  async blockIP(ip) {
    if (!confirm(`Заблокировать ${ip} в Windows Firewall (вход+выход)?`)) return;
    try {
      const res = await apiPost("fwblockip", { ip });
      toast(res.ok ? `IP ${ip} заблокирован` : "Не удалось (нужны права администратора)", !res.ok);
      this.fwList();
    } catch (e) { toast(String(e), true); }
  },

  /* ---------- diagnostics ---------- */
  setBox(id, html, muted = false) {
    const el = $(id);
    el.classList.toggle("muted", muted);
    el.innerHTML = html;
  },

  async pingProbe() {
    const target = $("ping-target").value.trim();
    this.setBox("ping-result", "Проверка…");
    try {
      const r = await apiGet(`ping?target=${encodeURIComponent(target)}&count=5`);
      const lines = r.results.map(p =>
        `<span style="color:${p.ok ? cssVar("--cyan") : cssVar("--danger")}">` +
        `${p.ok ? p.ms.toFixed(1) + "ms" : "потеря"}</span>`).join(" · ");
      this.setBox("ping-result",
        `<b>${esc(r.target)}</b>: средний ${r.avg_ms ?? "—"} ms, потери ${r.loss_pct}%<br>${lines}`);
    } catch (e) { this.setBox("ping-result", "Ошибка: " + e.message); }
  },

  async mtrStart() {
    const target = $("mtr-target").value.trim();
    try {
      await apiPost("mtrstart", { target, max_hops: 12, cycle_sec: 8 });
      window.MtrActive = true;
      this.setBox("mtr-result", "Запущен непрерывный анализ маршрута…");
      this.mtrPoll();
    } catch (e) { this.setBox("mtr-result", "Ошибка: " + e.message); }
  },
  async mtrStop() {
    await apiPost("mtrstop", {});
    window.MtrActive = false;
  },
  async mtrPoll(silent) {
    try {
      const st = await apiGet("mtrstats");
      if (!st.running && !silent && !st.cycles) {
        this.setBox("mtr-result", "Не запущен"); return;
      }
      if (!st.running && st.cycles === 0) return;
      const rows = st.hops.filter(h => h.ip !== "*" || h.sent).map(h => {
        const color = !h.avg_ms ? cssVar("--muted")
          : h.avg_ms < 45 ? cssVar("--cyan")
          : h.avg_ms < 120 ? cssVar("--amber") : cssVar("--danger");
        return `<div class="hop-line" style="display:flex;gap:9px;align-items:center;padding:2px 0">
          <span class="muted" style="width:24px">${h.hop}</span>
          <span class="mono" style="width:118px">${esc(h.ip)}</span>
          <span>${sparklineSVG(h.graph, color)}</span>
          <span style="width:56px;text-align:right;color:${color}">${h.avg_ms ?? "—"}</span>
          <span class="muted" style="width:64px;text-align:right">${h.loss_pct}% потерь</span>
        </div>`;
      }).join("");
      this.setBox("mtr-result",
        `<div class="muted" style="margin-bottom:6px">цель ${esc(st.target || "")} · циклов ${st.cycles}</div>${rows}`,
        false);
    } catch (e) { void e; }
  },

  async trace() {
    const target = $("trace-target").value.trim();
    this.setBox("trace-result", "Трассировка может занять до минуты…");
    try {
      const r = await apiGet(`trace?target=${encodeURIComponent(target)}&max=14`);
      this.renderTrace(r);
    } catch (e) { this.setBox("trace-result", "Ошибка: " + e.message); }
  },
  renderTrace(r) {
    const maxMs = Math.max(...r.hops.map(h => h.ms), 50);
    const rows = r.hops.map(h => {
      const wpx = Math.min(200, (h.ms / maxMs) * 200);
      const color = h.ip === "*" ? cssVar("--muted")
        : h.ms < 50 ? cssVar("--cyan") : h.ms < 140 ? cssVar("--amber") : cssVar("--danger");
      return `<div class="hop-line" style="display:flex;gap:9px;align-items:center;padding:3px 0">
        <span class="muted" style="width:24px">${h.hop}</span>
        <span class="mono" style="width:126px">${esc(h.ip)}</span>
        <span class="hop-bar" style="height:6px;border-radius:3px;background:${color};width:${wpx}px"></span>
        <span>${h.ip === "*" ? "—" : h.ms.toFixed(1) + "ms"}</span></div>`;
    }).join("");
    this.setBox("trace-result",
      `<div class="muted" style="margin-bottom:6px">Хопов: <b>${r.total_hops}</b>, средний ${Math.round(r.avg_ms)}ms</div>${rows}`);
  },
  async traceAll() {
    this.setBox("trace-result", "Трассировка всех целей из настроек…");
    try {
      const res = await apiGet("traceall");
      const parts = Object.entries(res).map(([t, r]) =>
        r.error ? `<div>${esc(t)}: ошибка</div>` :
        `<div style="margin-bottom:7px"><b>${esc(t)}</b>: ${Math.round(r.avg_ms)}ms, хопов ${r.total_hops}
         <button class="mini-btn" onclick="document.getElementById('trace-target').value='${esc(t)}';UI.trace()">детали</button></div>`);
      this.setBox("trace-result", parts.join(""));
    } catch (e) { this.setBox("trace-result", "Ошибка: " + e.message); }
  },

  async dnsBest() {
    this.setBox("dns-result", "Опрос DNS-серверов…");
    try {
      const b = await apiGet("dnsbest");
      this.setBox("dns-result",
        b.ping < 999
          ? `Лучший: <b style="color:${cssVar("--cyan")}">${esc(b.name)}</b> (${esc(b.ip)}) — ${b.ping.toFixed(0)}ms`
          : "Доступные DNS не найдены");
    } catch (e) { this.setBox("dns-result", "Ошибка: " + e.message); }
  },
  async dnsResolve() {
    this.setBox("dns-result", "Резолв доменов…");
    try {
      const r = await apiGet("dnsresolve");
      const rows = r.results.map(x => {
        const color = x.ms == null ? cssVar("--danger")
          : x.ms < 50 ? cssVar("--cyan") : x.ms < 150 ? cssVar("--amber") : cssVar("--danger");
        return `<div style="display:flex;gap:12px;padding:2px 0">
          <span style="width:150px">${esc(x.host)}</span>
          <span class="mono muted">${esc(x.ip || "—")}</span>
          <b style="margin-left:auto;color:${color}">${x.ms == null ? "ошибка" : x.ms + "ms"}</b></div>`;
      });
      this.setBox("dns-result", rows.join(""));
    } catch (e) { this.setBox("dns-result", "Ошибка: " + e.message); }
  },

  async speedtest() {
    const bytes = $("speedtest-size").value;
    this.setBox("speedtest-result", "Замер загрузки…");
    try {
      const r = await apiGet(`speedtest?bytes=${bytes}`);
      this.setBox("speedtest-result",
        `<b style="font-size:22px;color:${cssVar('--cyan')}">${r.mbps} Mbps</b> download · ` +
        `${fmtMB(r.bytes / 1048576)} MB за ${r.seconds}s`, false);
    } catch (e) { this.setBox("speedtest-result", "Нет доступа к серверу замера"); }
  },
  async speedtestUp() {
    this.setBox("speedtest-result", "Замер отдачи…");
    try {
      const r = await apiGet(`uploadtest?bytes=2000000`);
      this.setBox("speedtest-result",
        `<b style="font-size:22px;color:${cssVar('--violet')}">${r.mbps} Mbps</b> upload · ` +
        `отправлено ${fmtMB(r.bytes / 1048576)} MB за ${r.seconds}s<br>
         <span class="muted">${r.note || ""}</span>`, false);
    } catch (e) { this.setBox("speedtest-result", "Нет доступа к серверу замера"); }
  },
  async speedLog() {
    try {
      const d = await apiGet("speedlog");
      const rows = d.log.map(l =>
        `<div style="display:flex;gap:10px;padding:2px 0">
          <span class="muted mono">${esc(String(l.timestamp).slice(5, 16).replace("T", " "))}</span>
          <b>${l.mbps} Mbps</b><span class="muted">${l.direction}</span></div>`).join("");
      this.setBox("speedtest-result", rows || "история пуста");
    } catch (e) { void e; }
  },

  /* ---------- LAN ---------- */
  async lanScan() {
    const btn = $("lan-scan-btn");
    btn.disabled = true;
    this.setBox("lan-status", "Сканирование 254 адресов (пинг + ARP + reverse DNS)… до минуты");
    try {
      const d = await apiPost("lanscan", {});
      const devices = d.devices || [];
      this.renderLan(devices, []);
      this.setBox("lan-status",
        `Онлайн сейчас: <b>${devices.length}</b> устройств. Новые помечены бейджем NEW.`);
    } catch (e) {
      this.setBox("lan-status", "Ошибка: " + e.message);
    } finally {
      btn.disabled = false;
      this.lanDevices();
    }
  },
  renderLan(devices, dbDevices) {
    const map = {};
    for (const d of dbDevices || []) map[d.mac] = d;
    const tb = $("lan-table").querySelector("tbody");
    tb.innerHTML = devices.map(d => `
      <tr>
        <td class="mono">${esc(d.ip)}</td>
        <td class="mono">${esc(d.mac)}</td>
        <td>${esc(d.vendor || "—")} ${d.is_new ? '<span class="new-badge">NEW</span>' : ""}</td>
        <td>${esc(d.hostname || "-")}</td>
        <td class="muted">${esc((map[d.mac]?.first_seen || "—").slice(0, 16).replace("T", " "))}</td>
        <td class="muted">${esc((d.is_me ? "это этот ПК" : (map[d.mac]?.last_seen || "").slice(0, 16).replace("T", " ") || "—"))}</td>
        <td><button class="mini-btn" title="Скан портов устройства"
          onclick="document.getElementById('pscan-host').value='${esc(d.ip)}';UI.portScan()">
          <svg class="ic sm"><use href="#i-search"/></svg></button></td>
      </tr>`).join("") || '<tr><td colspan=7 class=muted>устройств не найдено</td></tr>';
  },
  async lanDevices() {
    try {
      const d = await apiGet("landevices");
      if (!($("lan-table").querySelector("tbody").children.length))
        this.renderLan([], d.devices);
    } catch (e) { void e; }
  },

  /* ---------- capture ---------- */
  async captureToggle() {
    if (this.captureOn) {
      await apiPost("capturestop", {});
      this.captureOn = false;
      $("capture-status").innerHTML = "Захват остановлен";
      $("capture-stats").classList.add("hidden");
    } else {
      const proto = $("capture-proto").value;
      const res = await apiPost("capturestart", { proto });
      if (!res.ok) {
        this.setBox("capture-status", res.error || "не удалось запустить");
        return;
      }
      this.captureOn = true;
      $("capture-status").innerHTML = "Идёт захват IPv4-пакетов с интерфейса по умолчанию…";
      this.captureRefresh(true);
    }
    const btn = $("capture-toggle");
    btn.innerHTML = this.captureOn
      ? '<svg class="ic sm"><use href="#i-stop"/></svg>Стоп'
      : '<svg class="ic sm"><use href="#i-play"/></svg>Старт';
  },
  async captureRefresh(resetTable) {
    try {
      const st = await apiGet("capturestate");
      $("capture-stats").classList.remove("hidden");
      $("capture-stats").innerHTML =
        `<span class="chip OK">всего ${st.stats.total}</span>` +
        `<span class="chip INFO">TCP ${st.stats.tcp}</span>` +
        `<span class="chip MEDIUM">UDP ${st.stats.udp}</span>` +
        `<span class="chip WARN">ICMP ${st.stats.icmp}</span>` +
        `<span class="chip HIGH">${fmtMB(st.stats.bytes / 1048576)} MB</span>`;
      const tb = $("capture-table").querySelector("tbody");
      const rows = st.packets.map(p => `
        <tr>
          <td class="muted">${new Date(p.ts * 1000).toLocaleTimeString("ru-RU")}</td>
          <td><span class="chip ${p.proto}">${esc(p.proto)}</span></td>
          <td>${esc(p.src)}</td><td>${esc(p.dst)}</td>
          <td>${esc(p.info || "")}</td><td>${p.len}</td>
        </tr>`);
      tb.innerHTML = (resetTable ? rows : rows.slice(0, 60)).join("");
    } catch (e) { void e; }
  },

  /* ---------- security / ids / portscan / fw ---------- */
  async securityScan(quick) {
    $("security-status").className = "result-box muted";
    $("security-status").textContent = quick ? "Быстрая проверка…" : "Полное сканирование…";
    $("security-results").innerHTML = "";
    try {
      const { job } = await apiPost("securityscan", { quick });
      const poll = async () => {
        const st = await apiGet(`securityresult?job=${job}`);
        if (st.status === "running") { setTimeout(poll, 1500); return; }
        if (st.status === "error") { $("security-status").textContent = st.error; return; }
        this.renderSecurity(st.result, quick);
      };
      poll();
    } catch (e) { $("security-status").textContent = e.message; }
  },
  renderSecurity(results, quick) {
    const total = Object.values(results).reduce((a, v) => a + (v?.length || 0), 0);
    $("security-status").className = "result-box";
    $("security-status").innerHTML = total === 0
      ? `Угроз не обнаружено (${quick ? "быстрая" : "полная"} проверка)`
      : `Находок: <b style="color:${cssVar("--amber")}">${total}</b>`;

    const wrap = $("security-results");
    wrap.innerHTML = "";
    for (const [cat, threats] of Object.entries(results)) {
      if (!threats || !threats.length) continue;
      const card = document.createElement("div");
      card.className = "card";
      card.style.cssText = "background:var(--panel2);margin-top:10px;padding:12px 14px";
      card.innerHTML = `<div class="card-title" style="margin-bottom:8px">${esc(cat)}
        <span class="chip HIGH">${threats.length}</span></div>` +
        threats.map(t => {
          const sev = t.severity || "LOW";
          const name = t.process || t.domain || t.entry || "Неизвестно";
          const extra = [
            t.remote ? "→ " + t.remote : "",
            t.redirects_to ? "→ " + t.redirects_to : "",
            t.connections != null ? t.connections + " соед." : "",
            t.path || "",
          ].filter(Boolean).join(" · ");
          return `<div style="display:flex;gap:11px;padding:4px 0;align-items:center;flex-wrap:wrap">
            <span class="chip ${sev}">${sev}</span>
            <b>${esc(String(name)).slice(0, 60)}</b>
            <span class="muted">${esc(t.reason || "")}</span>
            <span class="muted mono" style="margin-left:auto;font-size:11px">${esc(extra)}</span>
          </div>`;
        }).join("");
      wrap.appendChild(card);
    }
  },

  async loadIds() {
    try {
      const d = await apiGet("idsfeed");
      const feed = $("ids-feed");
      feed.className = "feed";
      feed.innerHTML = d.events.length ? d.events.map(e => `
        <div class="feed-item danger">
          <div class="fi-head"><span class="fi-type chip CRITICAL">${esc(e.type)}</span>
            <time class="time-stamp">${timeAgo(e.ts)}</time></div>
          <div class="fi-body">${esc(e.message)}</div></div>`).join("")
        : '<span class="muted">обнаружений нет — детекторы активны</span>';
      const badge = $("ids-badge");
      badge.textContent = d.events.length;
      badge.classList.toggle("hidden", !d.events.length);
    } catch (e) { void e; }
  },

  async portScan() {
    const host = $("pscan-host").value.trim();
    this.setBox("pscan-result", "Сканирование 30 популярных TCP-портов…");
    try {
      const r = await apiPost("portscan", { host });
      if (r.error) { this.setBox("pscan-result", "Ошибка: " + r.error); return; }
      const rows = r.open.length
        ? r.open.map(o => `<span class="chip OK" style="margin:2px">${o.port}${o.service ? " · " + o.service : ""}</span>`).join(" ")
        : '<span class="muted">открытых портов не найдено</span>';
      this.setBox("pscan-result",
        `<b>${esc(r.host)}</b>: проверено ${r.scanned} портов, открыто ${r.open.length}<br>${rows}`);
    } catch (e) { this.setBox("pscan-result", "Ошибка: " + e.message); }
  },

  async fwList() {
    try {
      const d = await apiGet("firewallrules");
      const feed = $("fw-list");
      feed.className = "feed";
      feed.innerHTML = d.rules.length ? d.rules.map(r => `
        <div class="feed-item">
          <div class="fi-head"><span class="fi-type mono">${esc(r.name)}</span>
            <span class="chip ${r.enabled === "yes" || r.enabled === "да" ? "OK" : "MEDIUM"}">${esc(r.enabled || "?")}</span>
            <button class="mini-btn right" onclick="UI.fwUnblock('${esc(r.name)}')">
              <svg class="ic sm"><use href="#i-x"/></svg></button></div>
          <div class="fi-body mono">${esc(r.remoteip || "")} ${esc(r.program || "")}</div>
        </div>`).join("") :
        '<span class="muted">правил NetPulse нет — заблокируйте IP из соединений или LAN</span>';
    } catch (e) { void e; }
  },
  async fwUnblock(name) {
    try {
      await apiPost("fwunblock", { name });
      this.fwList();
      toast("Правило удалено");
    } catch (e) { toast(String(e), true); }
  },

  /* ---------- ai ---------- */
  async loadAI() {
    try {
      const d = await apiGet("ai");
      $("ai-model").textContent = d.stats?.model_trained ? "обучена" : "не обучена";
      $("ai-model").style.color = d.stats?.model_trained ? cssVar("--cyan") : cssVar("--danger");
      $("ai-analyzed").textContent = d.stats?.total_analyzed ?? 0;
      $("ai-anomalies-n").textContent = d.stats?.anomalies_detected ?? 0;
      const fc = d.forecast;
      $("ai-prediction").innerHTML = fc ?
        `${fmtNum(fc.predicted_kbps_5min)}<span class="unit"> KB/s</span>` : "—";

      const feed = $("ai-anomaly-feed");
      feed.className = "feed";
      feed.innerHTML = d.anomalies.length ? d.anomalies.map(a => {
        const conf = a.confidence || 0;
        const f = a.features || {};
        return `<div class="feed-item unread">
          <div class="fi-head"><span class="fi-type chip ${conf > 0.8 ? "CRITICAL" : "WARN"}">аномалия ${(conf * 100).toFixed(0)}%</span>
            <time class="time-stamp">${esc(String(a.timestamp).slice(11, 19))}</time></div>
          <div class="fi-body mono">${Object.entries(f).map(([k, v]) =>
            `${k}: ${fmtNum(v)}`).join(" · ")}</div></div>`;
      }).join("") : "";
    } catch (e) { void e; }
  },
  async aiTrain() {
    $("ai-train-status").textContent = "Обучение на истории из БД…";
    try {
      const r = await apiPost("aitrain");
      $("ai-train-status").innerHTML = r.ok
        ? `Модель переобучена на ${r.samples} записях`
        : `Недостаточно данных (${r.samples}, нужно ≥ 10)`;
      this.loadAI();
    } catch (e) { $("ai-train-status").textContent = e.message; }
  },

  /* ---------- alerts ---------- */
  async loadAlerts() {
    try {
      const d = await apiGet("alerts?limit=120");
      const feed = $("alerts-feed");
      feed.className = "feed";
      feed.innerHTML = d.alerts.length ? d.alerts.map(a => {
        const dangerType = /КРИТ|ПОТЕРИ|SCAN|QUOTA|BLOCK/i.test(a.alert_type);
        return `<div class="feed-item ${a.acknowledged ? "" : "unread"} ${dangerType ? "danger" : ""}">
          <div class="fi-head"><span class="fi-type chip ${dangerType ? "CRITICAL" : "WARN"}">${esc(a.alert_type)}</span>
            <span class="muted">${a.acknowledged ? "принят" : "новый"}</span>
            <time class="time-stamp">${esc(String(a.timestamp).slice(5, 19).replace("T", " "))}</time></div>
          <div class="fi-body">${esc(a.message || "")}</div></div>`;
      }).join("") : "Алертов пока нет";
    } catch (e) { void e; }
  },
  async ackAll() {
    try {
      await apiPost("alertsack", {});
      this.loadAlerts();
      toast("Все алерты приняты");
    } catch (e) { toast(String(e), true); }
  },

  /* ---------- history ---------- */
  async loadHistory() {
    const hours = $("hist-range").value;
    try {
      const d = await apiGet(`dbhistory?hours=${hours}`);
      const buckets = d.buckets;
      drawHistChart("chart-hist", [
        { values: buckets.map(b => b.kbps) },
        { values: buckets.map(b => b.ping) },
      ]);
      drawHistChart("chart-hist-ping", [
        { values: buckets.map(b => b.jitter) },
        { values: buckets.map(b => b.loss) },
      ]);
    } catch (e) { toast(String(e), true); }
  },

  /* ---------- журнал работ ---------- */
  async loadJournal() {
    try {
      const d = await apiGet("journal?limit=200");
      const tb = $("journal-table").querySelector("tbody");
      const srcColor = { manual: "INFO", chat: "WARN", watchdog: "CRITICAL",
                         runbook: "INFO", backup: "WARN" };
      tb.innerHTML = d.entries.length ? d.entries.map(e => `
        <tr>
          <td class="mono">${esc(String(e.timestamp).slice(5, 16).replace("T", " "))}</td>
          <td><span class="chip ${srcColor[e.source] || "INFO"}">${esc(e.source)}</span></td>
          <td>${esc(e.user_name || e.host || "")}</td>
          <td>${esc(e.text)}</td>
          <td class="mono">${e.minutes ? e.minutes : ""}</td>
          <td><button class="mini-btn" title="удалить" onclick="UI.journalDel(${e.id})">✕</button></td>
        </tr>`).join("") : `<tr><td colspan="6" class="muted">Пока пусто — добавьте первую запись</td></tr>`;
      this.loadJournalReport();
      this.loadPlanner();
    } catch (e) { toast(String(e), true); }
  },
  async journalAdd() {
    const text = $("jr-text").value.trim();
    if (!text) { toast("Введите текст записи", true); return; }
    try {
      await apiPost("journaladd", {
        text,
        user: $("jr-user").value.trim(),
        minutes: parseInt($("jr-min").value || "0", 10),
        source: "manual",
      });
      $("jr-text").value = ""; $("jr-min").value = "";
      toast("Запись добавлена");
      this.loadJournal();
    } catch (e) { toast(String(e), true); }
  },
  async journalDel(id) {
    try {
      await apiPost("journaldel", { id });
      this.loadJournal();
    } catch (e) { toast(String(e), true); }
  },
  async loadJournalReport() {
    try {
      const r = await apiGet("journalreport?days=30");
      const src = (r.by_source || []).map(s =>
        `${esc(s.source)}: ${s.n} (${s.minutes} мин)`).join(" · ") || "нет данных";
      const users = (r.top_users || []).slice(0, 3).map(u =>
        `${esc(u.who)} — ${u.n}`).join(", ");
      const hosts = (r.top_hosts || []).slice(0, 3).map(h =>
        `${esc(h.host)} — ${h.n}`).join(", ");
      $("jr-report").innerHTML =
        `Записей: <b>${r.entries}</b> · Времени: <b>${r.minutes} мин</b> (${r.hours} ч)<br>` +
        `<span class="muted">По источникам:</span> ${src}` +
        (users ? `<br><span class="muted">Чаще всего:</span> ${users}` : "") +
        (hosts ? `<br><span class="muted">Топ машин:</span> ${hosts}` : "");
    } catch (e) { void e; }
  },

  /* ---------- парк ПК / сторож / runbooks ---------- */
  async loadPark() {
    try {
      const [h, ev, rb, fcd] = await Promise.all([
        apiGet("hosts"), apiGet("events?limit=60"), apiGet("runbooks"),
        apiGet("diskforecast")]);
      const wd = h.watchdog || {};
      $("park-status").textContent = wd.running
        ? `Сторож активен: обход каждые ${wd.interval_min} мин, машин в списке: ${wd.hosts.length}`
        : "Сторож выключен — включите в config.json: \"watchdog\": {\"enabled\": true}";
      $("park-table").querySelector("tbody").innerHTML = h.hosts.length
        ? h.hosts.map(m => {
            const score = m.health_score ?? 100;
            const color = score >= 80 ? "#22d3a7" : score >= 50 ? "#f5b942" : "#ff5c74";
            return `<tr style="cursor:pointer" onclick="UI.showHost(${m.id})">
              <td>${esc(m.name)}</td>
              <td class="mono">${esc(m.ip || "")}</td>
              <td class="muted">${esc((m.os || "").slice(0, 28))}</td>
              <td>${m.online ? "🟢" : "🔴"}</td>
              <td><span style="color:${color};font-weight:600">${score}</span></td>
              <td class="muted">${esc(String(m.last_seen || "").slice(5, 16).replace("T", " "))}</td>
            </tr>`;
          }).join("")
        : `<tr><td colspan="6" class="muted">Парк пуст — включите сторож или нажмите «Обход сейчас»</td></tr>`;
      $("events-table").querySelector("tbody").innerHTML = ev.events.length
        ? ev.events.map(x => {
            const sev = x.severity === "CRITICAL" ? "CRITICAL"
                      : x.severity === "HIGH" ? "WARN" : "INFO";
            return `<tr>
              <td class="mono">${esc(String(x.timestamp).slice(5, 16).replace("T", " "))}</td>
              <td>${esc(x.host || "")}</td>
              <td><span class="chip ${sev}">${esc(x.kind)}</span></td>
              <td class="muted">${esc(x.severity)}</td>
              <td>${esc(x.text)}</td>
            </tr>`;
          }).join("")
        : `<tr><td colspan="5" class="muted">Событий нет</td></tr>`;
      $("rb-list").innerHTML = rb.runbooks.length
        ? rb.runbooks.map(b =>
            `<div style="display:flex;align-items:center;gap:8px;margin:4px 0">
               <button class="btn accent" onclick="UI.runbookExec('${esc(b.id)}')">${esc(b.name)}</button>
               <span class="muted">${esc(b.description || b.scope)}${b.params?.length ? " · параметры: " + esc(b.params.join(", ")) : ""}</span>
             </div>`).join("")
        : "Runbooks не найдены";
      const forecasts = fcd.forecasts || [];
      $("disk-fc-status").textContent = forecasts.length
        ? `Прогноз по наклону за последние недели — машин на грани: ${forecasts.length}`
        : "История ещё копится: нужно 2+ замера за несколько дней (сторож сам пишет каждый обход)";
      $("diskfc-table").querySelector("tbody").innerHTML = forecasts.length
        ? forecasts.map(f => {
            const c = f.days_left <= 14 ? "#ff5c74" : f.days_left <= 45 ? "#f5b942" : "#22d3a7";
            return `<tr>
              <td>${esc(f.host)}</td>
              <td class="mono">${esc(f.drive)}</td>
              <td class="mono">${f.free_gb} GB</td>
              <td class="mono muted">${f.rate_gb_day} GB/день</td>
              <td><b style="color:${c}">~${f.days_left} дн</b></td>
            </tr>`;
          }).join("")
        : "";
    } catch (e) { toast(String(e), true); }
  },
  async watchdogPoll() {
    const btn = $("park-poll-btn");
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = "Опрос...";
    try {
      const r = await apiPost("watchdogpoll", {});
      $("park-status").textContent =
        `Обход завершён: опрошено ${r.polled ?? 0} машин`;
      this.loadPark();
    } catch (e) {
      btn.textContent = old; btn.disabled = false;
      toast(String(e), true);
      return;
    }
    btn.textContent = old; btn.disabled = false;
  },
  async healthRecompute() {
    try {
      await apiPost("healthrecompute", {});
      toast("Карма пересчитана");
      this.loadPark();
    } catch (e) { toast(String(e), true); }
  },
  async runbookExec(name) {
    if (!confirm(`Выполнить «${name}»?`)) return;
    try {
      const r = await apiPost("runbookexec", { name, params: {} });
      const out = $("rb-output");
      out.classList.remove("hidden");
      out.textContent = `[${r.ok ? "OK" : "FAIL"} код ${r.exit_code}, ${r.seconds}s]\n${r.output || "(без вывода)"}`;
      this.loadPark();
    } catch (e) { toast(String(e), true); }
  },

  /* ---------- карточка машины ---------- */
  _curHost: null,
  async showHost(id) {
    try {
      const d = await apiGet(`hostdetail?id=${id}`);
      if (d.error) { toast(d.error, true); return; }
      this._curHost = { name: d.name, ip: d.ip || d.name };
      const el = $("park-detail");
      const score = d.health_score ?? 100;
      const color = score >= 80 ? "#22d3a7" : score >= 50 ? "#f5b942" : "#ff5c74";
      let html =
        `<div style="display:flex;justify-content:space-between;align-items:center">
           <b>${esc(d.name)}</b>
           <span>
             <a class="btn ghost" href="/api/rdp?host=${encodeURIComponent(d.ip || d.name)}${Auth.suffix()}">RDP</a>
             <button class="btn ghost" onclick="UI.wakeCur()">WoL</button>
             <button class="btn ghost" onclick="UI.pingCur()">Ping</button>
             <button class="mini-btn" onclick="document.getElementById('park-detail').classList.add('hidden')">✕</button>
           </span>
         </div>
         <div class="muted">${esc(d.os || "")} · ${esc(d.ip || "ip?")} ·
           ${d.online ? "в сети" : "офлайн"} · карма <span style="color:${color}"><b>${score}</b></span></div>` +
        (d.cpu ? `<div class="muted">CPU: ${esc(d.cpu)}${d.ram_gb ? " · RAM: " + esc(d.ram_gb) + " GB" : ""}</div>` : "");
      if (d.karma_hist && d.karma_hist.length >= 2) {
        html += `<div class="muted">Карма (динамика): ${this.sparkline(d.karma_hist)}
                 <span class="mono">${Math.min(...d.karma_hist)}…${Math.max(...d.karma_hist)}</span></div>`;
      }
      if (d.software?.length)
        html += `<div class="muted" style="margin-top:4px">Установлено ПО: ${d.software.length} позиций (поиск — ниже)</div>`;
      const oldPing = $("card-ping-out");
      if (oldPing) oldPing.remove();
      el.innerHTML = html;
      el.classList.remove("hidden");
    } catch (e) { toast(String(e), true); }
  },
  sparkline(values) {
    const chars = "▁▂▃▄▅▆▇█";
    const mn = Math.min(...values), mx = Math.max(...values);
    const span = (mx - mn) || 1;
    return `<span class="mono" style="letter-spacing:1px">${values.map(v =>
      chars[Math.round((v - mn) / span * 7)]).join("")}</span>`;
  },
  async wakeCur() {
    if (!this._curHost) return;
    try {
      const r = await apiPost("wol", { host: this._curHost.ip || this._curHost.name });
      if (r.ok) { toast(`Magic packet отправлен (${r.mac})`); }
      else { toast(r.error, true); }
    } catch (e) { toast(String(e), true); }
  },
  async pingCur() {
    if (!this._curHost) return;
    const target = encodeURIComponent(this._curHost.ip || this._curHost.name);
    let out = $("card-ping-out");
    if (!out) {
      out = document.createElement("div");
      out.id = "card-ping-out";
      out.className = "result-box mono";
      $("park-detail").appendChild(out);
    }
    out.textContent = "Пингуем...";
    try {
      const r = await apiGet(`ping?target=${target}&count=4`);
      const ok = r.results.filter(x => x.ok).length;
      out.textContent = `Ping ${this._curHost.ip || this._curHost.name}: ` +
        `ответили ${ok}/4, avg ${r.avg_ms ?? "—"} ms, потери ${r.loss_pct}%`;
    } catch (e) { out.textContent = String(e); }
  },

  /* ---------- плановые работы ---------- */
  _plannerTasks: [],
  async loadPlanner() {
    try {
      const d = await apiGet("planner");
      this._plannerTasks = d.tasks || [];
      $("planner-status").textContent = d.enabled
        ? `Задач в плане: ${this._plannerTasks.length}`
        : `Планировщик выключен. Включите в config.json: "planner": {"enabled": true, "tasks": [{"name": "...", "every_days": 30}]}`;
      $("planner-table").querySelector("tbody").innerHTML =
        this._plannerTasks.length ? this._plannerTasks.map((t, i) => {
          const st = t.due
            ? `<span class="chip CRITICAL">просрочено</span>`
            : `<span class="chip INFO">ок</span>`;
          const left = t.days_left === null ? "" :
            t.days_left < 0 ? "ни разу" : `осталось ${t.days_left} дн`;
          return `<tr>
            <td>${esc(t.name)}</td>
            <td class="mono">${t.every_days} дн</td>
            <td>${st}<span class="muted"> ${left}</span></td>
            <td class="mono muted">${esc(t.last_done ? String(t.last_done).slice(0, 16).replace("T", " ") : "—")}</td>
            <td><button class="btn ghost" onclick="UI.plannerDone(${i})">Выполнено</button></td>
          </tr>`;
        }).join("") : `<tr><td colspan="5" class="muted">Задач нет</td></tr>`;
    } catch (e) { void e; }
  },
  async plannerDone(idx) {
    const t = this._plannerTasks[idx];
    if (!t) return;
    try {
      await apiPost("plannerdone", { name: t.name });
      toast(`Отмечено: ${t.name}`);
      this.loadPlanner();
    } catch (e) { toast(String(e), true); }
  },
  downloadReport() {
    location.href = "/journal.txt?days=30" + Auth.suffix();
  },

  /* ---------- софт парка ---------- */
  async softSearch() {
    try {
      const q = $("sw-q").value.trim();
      const d = await apiGet("softsearch?q=" + encodeURIComponent(q));
      $("sw-stats").textContent = q
        ? `Найдено: ${d.results.length}`
        : `Машин с отчётами: ${d.stats.hosts ?? 0} · позиций ПО: ${d.stats.packages ?? 0}`;
      $("sw-table").querySelector("tbody").innerHTML = d.results.length
        ? d.results.map(s => `<tr>
            <td>${esc(s.name)}</td>
            <td class="mono muted">${esc(s.version || "")}</td>
            <td class="muted">${esc(s.publisher || "")}</td>
            <td>${esc(s.host)}</td>
            <td class="mono">${esc(s.ip || "")}</td>
          </tr>`).join("")
        : `<tr><td colspan="5" class="muted">Ничего не найдено${q ? "" : " — отчёты ещё не приходили"}</td></tr>`;
    } catch (e) { toast(String(e), true); }
  },

  /* ---------- виджет дашборда ---------- */
  async loadDashPlatform() {
    try {
      const [h, r] = await Promise.all([
        apiGet("hosts"), apiGet("journalreport?days=1")]);
      const worst = h.hosts.filter(x => x.health_score < 80)
        .sort((a, b) => a.health_score - b.health_score).slice(0, 3);
      let html = "";
      if (worst.length)
        html += worst.map(m => {
          const c = m.health_score >= 50 ? "#f5b942" : "#ff5c74";
          return `${esc(m.name)}: <span style="color:${c};font-weight:600">${m.health_score}</span>`;
        }).join("<br>");
      else
        html += `<span class="muted">парк здоров</span>`;
      html += `<br>Журнал за сутки: <b>${r.entries ?? 0}</b> (${r.minutes ?? 0} мин)`;
      $("dash-platform").innerHTML = html;
    } catch (e) { void e; }
  },


  /* ---------- settings ---------- */
  async loadSettings() {
    try {
      const cfg = await apiGet("settings");
      $("set-ping-target").value = cfg.ping_target || "8.8.8.8";
      $("set-good-ping").value = cfg.quality?.good_ping_ms ?? 50;
      $("set-warn-ping").value = cfg.quality?.warn_ping_ms ?? 120;
      $("set-max-jitter").value = cfg.quality?.max_jitter_ms ?? 15;
      $("set-max-loss").value = cfg.quality?.max_loss_pct ?? 2;
      $("set-quota-day").value = cfg.quota?.daily_mb ?? 0;
      $("set-quota-month").value = cfg.quota?.monthly_gb ?? 0;
      $("set-ai-enabled").checked = !!cfg.ai?.enabled;
      $("set-anomaly").value = cfg.ai?.anomaly_threshold ?? 0.6;
      $("set-cleanup").value = cfg.db_cleanup_days ?? 30;
      $("set-ports").value = (cfg.security?.suspicious_ports || []).join(", ");
      $("set-ids-th").value = cfg.security?.scan_detection_threshold ?? 15;
      $("set-auth").checked = !!cfg.web_auth_enabled;
      $("set-token").value = cfg.web_token_masked ||
        (cfg.web_token ? cfg.web_token.slice(0, 6) + "..." + cfg.web_token.slice(-4) : "");
      $("set-tg-on").checked = !!cfg.telegram?.enabled;
      $("set-tg-token").value = cfg.telegram?.token || "";
      $("set-tg-chat").value = cfg.telegram?.chat_id || "";
      $("set-backup-on").checked = !!cfg.backup?.enabled;
      $("set-backup-time").value = cfg.backup?.time || "03:00";
      $("set-backup-keep").value = cfg.backup?.keep ?? 7;
    } catch (e) { if (e instanceof UnauthorizedError) this.showLogin(); else toast(String(e), true); }
  },
  async regenToken() {
    try {
      await apiPost("settings", { _regen_token: true });
      await this.loadSettings();
      toast("Токен обновлён — войдите заново с новым токеном");
    } catch (e) { toast(String(e), true); }
  },
  async saveSettings() {
    try {
      const portsRaw = $("set-ports").value;
      await apiPost("settings", {
        ping_target: $("set-ping-target").value.trim(),
        quality: {
          good_ping_ms: +$("set-good-ping").value || 50,
          warn_ping_ms: +$("set-warn-ping").value || 120,
          max_jitter_ms: +$("set-max-jitter").value || 15,
          max_loss_pct: +$("set-max-loss").value || 2,
        },
        quota: {
          daily_mb: +$("set-quota-day").value || 0,
          monthly_gb: +$("set-quota-month").value || 0,
        },
        ai: {
          enabled: $("set-ai-enabled").checked,
          anomaly_threshold: Math.min(0.95, Math.max(0.1, +$("set-anomaly").value || 0.6)),
        },
        db_cleanup_days: +$("set-cleanup").value || 30,
        security: {
          suspicious_ports: portsRaw.split(",").map(s => parseInt(s.trim())).filter(n => !isNaN(n)),
          scan_detection_threshold: +$("set-ids-th").value || 15,
        },
        web_auth_enabled: $("set-auth").checked,
        telegram: {
          enabled: $("set-tg-on").checked,
          token: $("set-tg-token").value.trim(),
          chat_id: $("set-tg-chat").value.trim(),
        },
        backup: {
          enabled: $("set-backup-on").checked,
          time: $("set-backup-time").value.trim() || "03:00",
          keep: +$("set-backup-keep").value || 7,
        },
      });
      $("settings-status").innerHTML =
        `Сохранено и применено (${new Date().toLocaleTimeString("ru-RU")})`;
      toast("Настройки применены");
    } catch (e) {
      $("settings-status").textContent = e.message;
    }
  },
  async backupRun() {
    try {
      const r = await apiPost("backuprun");
      if (r.ok) {
        const list = await apiGet("backuplist");
        const names = (list.backups || []).slice(0, 5)
          .map(b => `${b.name} (${b.size_mb} MB)`).join("<br>");
        $("settings-status").innerHTML =
          `Копия создана: <span class="mono">${esc(r.archive)}</span><br>` +
          `<span class="muted">Последние копии в ${esc(list.dir || "")}:<br>${names}</span>`;
      } else {
        $("settings-status").textContent = `Ошибка: ${r.error || ""}`;
      }
    } catch (e) { toast(String(e), true); }
  },
};

window.UI = UI;
window.MtrActive = false;
document.addEventListener("DOMContentLoaded", () => UI.init());
