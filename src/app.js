
const { invoke } = window.__TAURI__.core;
const { getCurrentWindow } = window.__TAURI__.window;
const { listen } = window.__TAURI__.event;

const win = getCurrentWindow();

const APP_VERSION = "1.9";
let _UPDATE_CHECKED = false;

const DEFAULTS = { bg1: "#1f2937", bg2: "#374151", bg3: "#111827", bg4: "#000000", anim_speed: 1.0 };
const THEME = Object.assign({}, DEFAULTS);
const BASE_DURATION = 21000;

function applyTheme() {
  const r = document.documentElement.style;
  r.setProperty("--bg1", THEME.bg1);
  r.setProperty("--bg2", THEME.bg2);
  r.setProperty("--bg3", THEME.bg3);
  r.setProperty("--bg4", THEME.bg4);
  r.setProperty("--accent", THEME.bg1);
  const g = document.getElementById("gradient");
  if (THEME.anim_speed <= 0) {
    g.style.animationPlayState = "paused";
  } else {
    g.style.animationPlayState = "running";
    g.style.animationDuration = (BASE_DURATION / THEME.anim_speed) + "ms";
  }
}

const saveThemeDebounced = debounce(() => {
  invoke("save_theme", { theme: { ...THEME } }).catch(() => {});
}, 150);

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function toast(msg, ms = 2600) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  document.getElementById("toasts").appendChild(t);
  setTimeout(() => t.remove(), ms);
}

function debounce(fn, wait) {
  let h = null;
  return function (...a) {
    clearTimeout(h);
    h = setTimeout(() => fn.apply(this, a), wait);
  };
}

const modals = {};

function openModal(id, name) {
  const container = document.getElementById("modals");
  container.innerHTML = "";
  const el = document.createElement("div");
  el.className = "modal";
  el.innerHTML =
    '<div class="m-icon">&#11015;</div>' +
    '<div class="m-title">' + esc(name) + "</div>" +
    '<div class="m-progress"><div class="bar"></div></div>' +
    '<div class="m-pct">0%</div>';
  container.appendChild(el);
  const bar = el.querySelector(".bar");
  const pct = el.querySelector(".m-pct");
  const title = el.querySelector(".m-title");
  const ctrl = {
    el,
    setProgress(v) { bar.style.width = Math.max(0, Math.min(100, v)) + "%"; pct.textContent = v + "%"; },
    setStatus(s) { title.textContent = s; },
    success(path) {
      el.innerHTML =
        '<div class="m-ok">&#10003;</div>' +
        '<div class="m-title">Complete!</div>' +
        '<div class="m-path">Saved to: ' + esc(path) + "</div>";
      const b = document.createElement("button");
      b.className = "m-close";
      b.textContent = "Close";
      b.onclick = () => { delete modals[id]; el.remove(); };
      el.appendChild(b);
    },
    fail(info) {
      el.className = "modal error";
      el.innerHTML =
        '<div class="m-err">&#10005;</div>' +
        '<div class="m-title">' + esc(info) + "</div>";
      const b = document.createElement("button");
      b.className = "m-close";
      b.textContent = "Close";
      b.onclick = () => { delete modals[id]; el.remove(); };
      el.appendChild(b);
    },
  };
  modals[id] = ctrl;
  return ctrl;
}

function newJobId(prefix) {
  return prefix + "_" + Date.now() + "_" + Math.floor(Math.random() * 1e6);
}

listen("job", (ev) => {
  const { id, kind, value } = ev.payload;
  const m = modals[id];
  if (!m) return;
  if (kind === "progress") m.setProgress(value);
  else if (kind === "status") m.setStatus(value);
});

async function downloadWithModal(url, name) {
  const dest = await invoke("pick_folder");
  if (!dest) return null;
  const id = newJobId("dl");
  const m = openModal(id, name);
  m.setStatus("Downloading " + name + "...");
  const res = await invoke("download", { id, url, dest, name });
  if (res.ok) m.success(res.info);
  else m.fail(res.info);
  return res;
}

document.querySelectorAll(".bulb").forEach((b) => {
  b.addEventListener("click", async () => {
    const role = b.dataset.role;
    try {
      if (role === "close") await win.close();
      else if (role === "min") await win.minimize();
      else await win.toggleMaximize();
    } catch (e) { /* ignore */ }
  });
});

const DIR = {
  n: "North", s: "South", e: "East", w: "West",
  ne: "NorthEast", nw: "NorthWest", se: "SouthEast", sw: "SouthWest",
};
document.querySelectorAll(".rz").forEach((h) => {
  h.addEventListener("mousedown", async (e) => {
    e.preventDefault();
    const key = [...h.classList].find((c) => DIR[c]);
    if (!key) return;
    try { await win.startResizeDragging(DIR[key]); } catch (_) { /* ignore */ }
  });
});

let currentPage = "add";

function navigate(page) {
  currentPage = page;
  document.querySelectorAll(".page").forEach((p) => p.classList.toggle("active", p.id === "page-" + page));
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.page === page));
  if (page === "library") loadLibrary();
}

document.querySelectorAll(".nav-btn").forEach((b) => {
  b.addEventListener("click", () => navigate(b.dataset.page));
});

document.querySelectorAll(".tog").forEach((b) => {
  b.addEventListener("click", () => {
    const on = !b.classList.contains("off");
    b.classList.toggle("off", on);
    const em = b.querySelector("em");
    if (em) em.textContent = on ? "OFF" : "ON";
  });
});

document.getElementById("btn-steam").addEventListener("click", async () => {
  const r = await invoke("launch_steam");
  if (!r.ok) toast(r.msg);
  else toast("Launching Steam...");
});

document.getElementById("btn-reset").addEventListener("click", async () => {
  if (!confirm("Restart Steam now?\nAll Steam processes will be closed and Steam will be relaunched.")) return;
  toast("Restarting Steam...");
  await invoke("reset_steam");
});

document.getElementById("btn-cloud").addEventListener("click", async () => {
  if (!confirm("Close Steam completely then click OK.")) return;
  toast("Running cloud fix...");
  const r = await invoke("cloud_fix");
  if (r.ok) toast("Backup: " + r.info, 6000);
  else toast("Error: " + r.info, 6000);
});

let providers = [];
let selectedAppid = null;

async function loadProviders(selectKey) {
  providers = await invoke("list_providers");
  const sel = document.getElementById("provider");
  const prev = selectKey || sel.value || "auto";
  sel.innerHTML = '<option value="auto">Auto — best available</option>';
  providers.filter((p) => !p.builtin).forEach((p) => {
    const o = document.createElement("option");
    o.value = p.key;
    o.textContent = p.name || p.key;
    sel.appendChild(o);
  });
  if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
  updateProviderHint();
}

function updateProviderHint() {
  const sel = document.getElementById("provider");
  const hint = document.getElementById("provider-hint");
  if (sel.value === "auto") hint.textContent = "Automatically finds the best available source.";
  else hint.textContent = "Uses your provider: " + sel.options[sel.selectedIndex].textContent;
}

document.getElementById("provider").addEventListener("change", updateProviderHint);

document.querySelectorAll('input[name="addmode"]').forEach((r) => {
  r.addEventListener("change", () => {
    const search = document.querySelector('input[name="addmode"]:checked').value === "search";
    document.getElementById("search-name").classList.toggle("hidden", !search);
    document.getElementById("manual-appid").classList.toggle("hidden", search);
    document.getElementById("search-results").classList.toggle("hidden", !search);
  });
});

const doSearch = debounce(async (text) => {
  text = text.trim();
  const results = document.getElementById("search-results");
  if (text.length < 2) { results.innerHTML = ""; return; }
  document.getElementById("add-status").textContent = "Searching...";
  const items = await invoke("steam_search", { text });
  results.innerHTML = "";
  items.slice(0, 30).forEach((it) => {
    const d = document.createElement("div");
    d.className = "list-item";
    d.innerHTML = '<div class="item-info"><div class="item-name">' + esc(it.name) +
      '</div><div class="item-sub">ID: ' + esc(it.id) + "</div></div>";
    d.addEventListener("click", () => {
      selectedAppid = it.id;
      document.getElementById("dl-script").disabled = false;
      document.getElementById("add-status").textContent = "Selected: " + it.name + " (" + it.id + ")";
    });
    results.appendChild(d);
  });
  document.getElementById("add-status").textContent = "Found " + items.length + " results";
}, 320);

document.getElementById("search-name").addEventListener("input", (e) => {
  if (document.querySelector('input[name="addmode"]:checked').value === "search") doSearch(e.target.value);
});

document.getElementById("dl-script").addEventListener("click", async () => {
  const manual = document.querySelector('input[name="addmode"]:checked').value === "manual";
  const appid = manual ? document.getElementById("manual-appid").value.trim() : selectedAppid;
  if (!appid || !/^\d+$/.test(appid)) {
    document.getElementById("add-status").textContent = "Invalid AppID";
    return;
  }
  const btn = document.getElementById("dl-script");
  btn.disabled = true;
  document.getElementById("add-status").textContent = "Downloading...";
  const provider = document.getElementById("provider").value || "auto";
  const id = newJobId("man");
  const statusFn = (s) => { document.getElementById("add-status").textContent = s; };
  const off = await listen("job", (ev) => {
    if (ev.payload.id === id && ev.payload.kind === "status") statusFn(ev.payload.value);
  });
  const res = await invoke("manifest_download", { id, appid, provider });
  off();
  document.getElementById("add-status").textContent = (res.ok ? "✅ " : "❌ ") + res.msg;
  btn.disabled = false;
  if (res.ok) loadLibrary();
});

async function handleDropLua(path) {
  const r = await invoke("install_lua", { path });
  document.getElementById("add-status").textContent = (r.ok ? "✅ " : "❌ ") + r.msg;
}


document.getElementById("add-provider").addEventListener("click", () => {
  const container = document.getElementById("modals");
  container.innerHTML = "";
  const el = document.createElement("div");
  el.className = "modal dlg";
  el.innerHTML =
    '<div class="m-title">Add a custom provider</div>' +
    '<div class="dlg-desc">The URL may contain {appid} — it is replaced with the game\'s AppID.</div>' +
    '<div class="dlg-row"><label>Name</label><input class="input" id="pv-name" placeholder="My Provider"></div>' +
    '<div class="dlg-row"><label>URL</label><input class="input" id="pv-url" placeholder="https://example.com/{appid}.zip"></div>' +
    '<div class="dlg-err" id="pv-err"></div>' +
    '<div class="dlg-btns"><button class="btn" id="pv-cancel">Cancel</button><button class="btn grad" id="pv-ok">Add</button></div>';
  container.appendChild(el);
  const close = () => { el.remove(); };
  el.querySelector("#pv-cancel").onclick = close;
  el.querySelector("#pv-ok").onclick = async () => {
    const name = el.querySelector("#pv-name").value.trim();
    const url = el.querySelector("#pv-url").value.trim();
    const r = await invoke("add_provider", { name, url });
    if (!r.ok) { el.querySelector("#pv-err").textContent = r.msg; return; }
    close();
    await loadProviders(r.key);
    toast("Provider '" + r.name + "' added");
  };
});


document.getElementById("del-provider").addEventListener("click", async () => {
  const sel = document.getElementById("provider");
  const key = sel.value;
  const status = document.getElementById("add-status");
  if (!key || key === "auto") { status.textContent = "❌ Select a custom provider first"; return; }
  const target = providers.find((p) => p.key === key);
  if (!target) { status.textContent = "❌ Provider not found"; return; }
  if (!confirm("Delete '" + (target.name || key) + "'?")) return;
  await invoke("remove_provider", { key });
  await loadProviders("auto");
  status.textContent = "🗑 Provider deleted";
});


win.onDragDropEvent((e) => {
  const dz = document.getElementById("dropzone");
  const p = e.payload;
  if (p.type === "enter" || p.type === "over") dz.classList.add("over");
  else if (p.type === "leave") dz.classList.remove("over");
  else if (p.type === "drop") {
    dz.classList.remove("over");
    if (currentPage !== "add") return;
    const lua = (p.paths || []).find((x) => x.toLowerCase().endsWith(".lua"));
    if (lua) handleDropLua(lua);
  }
});

let libAll = [];

async function loadLibrary() {
  const list = document.getElementById("lib-list");
  document.getElementById("lib-count").textContent = "...";
  const games = await invoke("library_games");
  libAll = games.map((g) => ({ ...g, widget: null, name: null }));
  document.getElementById("lib-count").textContent = games.length + " Games";
  list.innerHTML = "";
  if (!games.length) {
    list.innerHTML = '<div class="status-line" style="text-align:center;padding:30px">No lua scripts</div>';
    return;
  }
  const BATCH = 40;
  let i = 0;
  const renderMore = () => {
    const end = Math.min(i + BATCH, libAll.length);
    for (; i < end; i++) list.appendChild(makeLibItem(libAll[i]));
  };
  renderMore();
  list.onscroll = () => {
    if (list.scrollTop + list.clientHeight > list.scrollHeight - 300) renderMore();
  };
  libAll.forEach((g) => refreshLibInfo(g));
}

function makeLibItem(g) {
  const el = document.createElement("div");
  el.className = "list-item";
  const numeric = /^\d+$/.test(g.appid);
  el.innerHTML =
    '<div class="item-ico">&#127918;</div>' +
    '<div class="item-info"><div class="item-name">' + (numeric ? "Loading..." : esc(g.appid)) +
    '</div><div class="item-sub">AppID: ' + esc(g.appid) + "</div></div>" +
    '<div class="item-actions"></div>';
  const actions = el.querySelector(".item-actions");
  const nameEl = el.querySelector(".item-name");
  const icoEl = el.querySelector(".item-ico");
  g.widget = el; g.nameEl = nameEl; g.icoEl = icoEl;

  const del = document.createElement("button");
  del.className = "mini del";
  del.innerHTML = "&#128465;";
  del.onclick = async () => {
    if (!confirm("Delete " + g.appid + "?")) return;
    const r = await invoke("delete_lua", { appid: g.appid, path: g.path });
    if (r.ok) { toast("Deleted " + r.appid); loadLibrary(); }
    else toast("Failed " + r.appid);
  };

  if (numeric) {
    invoke("game_install_info", { appid: g.appid }).then((info) => {
      const btn = document.createElement("button");
      if (info.installed) {
        btn.className = "mini launch";
        btn.textContent = "▶  Launch";
        btn.onclick = () => launchGame(g.appid, info.dir);
      } else {
        btn.className = "mini dl";
        btn.textContent = "⬇  Download";
        btn.onclick = () => downloadGameScript(g.appid);
      }
      actions.appendChild(btn);
      actions.appendChild(del);
    });
  } else {
    actions.appendChild(del);
  }
  return el;
}

async function refreshLibInfo(g) {
  if (!/^\d+$/.test(g.appid)) return;
  const info = await invoke("library_info", { appid: g.appid });
  if (g.nameEl) g.nameEl.textContent = info.name;
  if (g.icoEl && info.image) {
    g.icoEl.style.backgroundImage = "url('" + info.image + "')";
    g.icoEl.innerHTML = "";
  }
}

async function launchGame(appid, dir) {
  const r = await invoke("launch_game", { appid, dir });
  if (r.ok) { toast("Launching " + r.info + "  (Steam not required)..."); return; }
  if (!confirm(r.info + ".\nLocate the game's .exe manually?")) { toast(r.info); return; }
  const fp = await invoke("pick_exe", { start: dir || null });
  if (!fp) return;
  const r2 = await invoke("launch_exe", { path: fp, appid });
  if (r2.ok) toast("Launching " + r2.info + "  (Steam not required)...");
  else toast("Launch failed: " + r2.info);
}

async function downloadGameScript(appid) {
  const id = newJobId("lib");
  toast("Downloading script for " + appid + "...");
  const off = await listen("job", (ev) => {
    if (ev.payload.id === id && ev.payload.kind === "status") toast(ev.payload.value, 1500);
  });
  const res = await invoke("manifest_download", { id, appid, provider: "auto" });
  off();
  toast((res.ok ? "✅ " : "❌ ") + res.msg, 4000);
  if (res.ok) loadLibrary();
}

document.getElementById("lib-refresh").addEventListener("click", () => loadLibrary());
document.getElementById("lib-search").addEventListener("input", (e) => {
  const t = e.target.value.toLowerCase().trim();
  libAll.forEach((g) => {
    if (!g.widget) return;
    const name = (g.nameEl ? g.nameEl.textContent : g.appid).toLowerCase();
    g.widget.style.display = (!t || name.includes(t) || g.appid.includes(t)) ? "" : "none";
  });
});

const COLOR_ROWS = [
  ["bg1", "Color 1 — Primary"],
  ["bg2", "Color 2 — Secondary"],
  ["bg3", "Color 3 — Accent"],
  ["bg4", "Color 4 — Background tail"],
];

function hexToRgb(hex) {
  const h = hex.replace("#", "");
  return [parseInt(h.slice(0, 2), 16) || 0, parseInt(h.slice(2, 4), 16) || 0, parseInt(h.slice(4, 6), 16) || 0];
}
function rgbToHex(r, g, b) {
  const f = (n) => Math.max(0, Math.min(255, n)).toString(16).padStart(2, "0");
  return "#" + f(r) + f(g) + f(b);
}

function buildColorRows() {
  const host = document.getElementById("color-rows");
  host.innerHTML = "";
  COLOR_ROWS.forEach(([key, label]) => {
    const row = document.createElement("div");
    row.className = "crow";
    row.innerHTML = '<div class="crow-label">' + esc(label) + '</div><div class="swatch"></div>';
    const sliders = {};
    ["R", "G", "B"].forEach((comp) => {
      const lbl = document.createElement("div");
      lbl.className = "comp";
      lbl.textContent = comp;
      const s = document.createElement("input");
      s.type = "range"; s.min = "0"; s.max = "255"; s.value = "0"; s.style.width = "140px";
      sliders[comp] = s;
      row.appendChild(lbl);
      row.appendChild(s);
    });
    const hexlbl = document.createElement("div");
    hexlbl.className = "hex";
    row.appendChild(hexlbl);
    host.appendChild(row);

    const swatch = row.querySelector(".swatch");
    const refresh = () => {
      const [r, g, b] = [sliders.R.value, sliders.G.value, sliders.B.value];
      const hex = rgbToHex(+r, +g, +b);
      swatch.style.background = hex;
      hexlbl.textContent = hex;
      THEME[key] = hex;
      applyTheme();
      saveThemeDebounced();
    };
    Object.values(sliders).forEach((s) => s.addEventListener("input", refresh));

    const [r, g, b] = hexToRgb(THEME[key]);
    sliders.R.value = r; sliders.G.value = g; sliders.B.value = b;
    swatch.style.background = THEME[key];
    hexlbl.textContent = THEME[key];
  });
}

function syncSettings() {
  const host = document.getElementById("color-rows");
  const rows = host.querySelectorAll(".crow");
  COLOR_ROWS.forEach(([key], idx) => {
    const row = rows[idx];
    if (!row) return;
    const [r, g, b] = hexToRgb(THEME[key]);
    const sliders = row.querySelectorAll('input[type="range"]');
    sliders[0].value = r; sliders[1].value = g; sliders[2].value = b;
    row.querySelector(".swatch").style.background = THEME[key];
    row.querySelector(".hex").textContent = THEME[key];
  });
  const sp = document.getElementById("speed");
  sp.value = Math.round(THEME.anim_speed * 100);
  document.getElementById("speed-lbl").textContent = THEME.anim_speed <= 0 ? "Paused" : sp.value + "%";
}

document.getElementById("speed").addEventListener("input", (e) => {
  THEME.anim_speed = e.target.value / 100;
  document.getElementById("speed-lbl").textContent = THEME.anim_speed <= 0 ? "Paused" : e.target.value + "%";
  applyTheme();
  saveThemeDebounced();
});

document.getElementById("reset-theme").addEventListener("click", () => {
  Object.assign(THEME, DEFAULTS);
  applyTheme();
  syncSettings();
  invoke("save_theme", { theme: { ...THEME } }).catch(() => {});
});

let lastUpdateInfo = null;
const updStatus = () => document.getElementById("upd-status");
const updDlBtn = () => document.getElementById("upd-dl");

async function checkUpdate(manual) {
  const btn = document.getElementById("upd-check");
  btn.disabled = true;
  btn.textContent = "⏳  Checking...";
  if (manual) {
    updStatus().textContent = "Contacting update server...";
    updDlBtn().classList.add("hidden");
  }
  let res;
  try { res = await invoke("check_update"); }
  catch (e) { res = { kind: "error", info: null }; }
  btn.disabled = false;
  btn.innerHTML = "&#128269;   Check for Update";

  const kind = res && res.kind;
  const info = res && res.info;
  if (kind === "error") {
    if (manual) updStatus().textContent = "⚠️ Could not check for updates. Try again later.";
    return null;
  }
  if (!info || typeof info !== "object") {
    if (manual) updStatus().textContent = "⚠️ Invalid update data.";
    return null;
  }
  const v = info.v || "?";
  const rel = info.published_rel || "unknown";
  const notes = (info.notes || "").trim();

  if (kind === "latest") {
    updDlBtn().classList.add("hidden");
    updStatus().textContent =
      "✅ You are on the latest version.\n" +
      "Latest release: v" + v + "\n" +
      "Released: " + rel;
    return info;
  }

  lastUpdateInfo = info;
  let preview = "";
  if (notes) preview = "\n\nRelease notes:\n" + notes.slice(0, 400) + (notes.length > 400 ? "..." : "");
  updStatus().textContent =
    "🚀 New version available!\n" +
    "Installed:  v" + APP_VERSION + "\n" +
    "Latest:      v" + v + "\n" +
    "Released:  " + rel + preview;
  updDlBtn().classList.remove("hidden");
  return info;
}

document.getElementById("upd-check").addEventListener("click", () => checkUpdate(true));
updDlBtn().addEventListener("click", () => {
  if (!lastUpdateInfo) return;
  const link = lastUpdateInfo.browser_link || lastUpdateInfo.link || "";
  if (!link) { toast("No download link available."); return; }
  invoke("open_url", { url: link });
});

function showUpdateDialog(info) {
  const container = document.getElementById("modals");
  container.innerHTML = "";
  const el = document.createElement("div");
  el.className = "modal dlg update-dlg";
  const notes = info.notes || "";
  el.innerHTML =
    '<div class="m-title" style="align-self:flex-start">&#128640;  Update Available</div>' +
    '<div class="update-box">' +
      '<div class="u-line dim">Current version:  v' + APP_VERSION + "</div>" +
      '<div class="u-line good">Latest version:    v' + esc(info.v || "?") + "</div>" +
      (info.published_rel && info.published_rel !== "unknown"
        ? '<div class="u-line blue">Released:          ' + esc(info.published_rel) + "</div>" : "") +
      '<div class="u-line dim2">Source:            ' + esc(info.source || "unknown") + "</div>" +
    "</div>" +
    (notes
      ? '<div class="u-notes-title">Release notes</div>' +
        '<div class="u-notes">' + esc(notes.slice(0, 1500)) + (notes.length > 1500 ? "\n..." : "") + "</div>"
      : "") +
    '<div class="dlg-btns">' +
      '<button class="btn" id="up-later">Later</button>' +
      '<button class="btn upd-dl" id="up-now">&#127760; Download in Browser</button>' +
    "</div>";
  container.appendChild(el);
  const close = () => el.remove();
  el.querySelector("#up-later").onclick = close;
  el.querySelector("#up-now").onclick = () => {
    const link = info.browser_link || info.link || "";
    if (link) invoke("open_url", { url: link });
    close();
  };
}

async function autoCheckUpdate() {
  if (_UPDATE_CHECKED) return;
  _UPDATE_CHECKED = true;
  let res;
  try { res = await invoke("check_update"); }
  catch (e) { return; }
  if (!res || res.kind !== "new" || !res.info) return;
  const info = res.info;
  const link = info.browser_link || info.link || "";
  if (!link) return;
  showUpdateDialog(info);
}

(async function init() {
  try {
    const t = await invoke("load_theme");
    if (t && typeof t === "object") Object.assign(THEME, t);
  } catch (e) { /* ignore */ }
  applyTheme();
  buildColorRows();
  syncSettings();
  try { await loadProviders(); } catch (e) { /* ignore */ }
  navigate("add");
  
  setTimeout(autoCheckUpdate, 1200);
})();
