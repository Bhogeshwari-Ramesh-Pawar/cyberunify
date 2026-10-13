// CyberUnify dashboard.
// Log fields come from external tools and can contain attacker-controlled text (usernames,
// URLs, user-agents), so everything is rendered with textContent — never innerHTML.

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];

function h(tag, attrs = {}, children = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "on") for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
    else if (k === "style") n.style.cssText = v;
    else if (k === "value") n.value = v;
    else if (k === "checked") n.checked = !!v;
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of [].concat(children)) if (c != null && c !== "" && c !== false) n.append(c);
  return n;
}

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = data.detail;
    throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg).join("; ") : `${res.status} ${res.statusText}`);
  }
  return data;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 2800);
}

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const LEVELS = ["critical", "high", "medium", "low", "info"];
const label = (s) => String(s ?? "").replace(/_/g, " ");
const fmtTime = (iso) => new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const ago = (iso) => {
  if (!iso) return "never";
  const m = Math.round((Date.now() - new Date(iso)) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  if (m < 1440) return `${Math.round(m / 60)}h ago`;
  return `${Math.round(m / 1440)}d ago`;
};
const pill = (score, level) => h("span", { class: `pill ${level}`, title: `${level} risk` }, `${Math.round(score)}`);
const bar = (pct, color) => h("div", { class: "bar" }, h("i", { style: `width:${Math.max(2, Math.min(100, pct))}%;background:${color}` }));

// One stable colour per tool, used everywhere (charts, badges, cards).
const PALETTE = ["#60a5fa", "#f0abfc", "#fbbf24", "#34d399", "#f87171", "#22d3ee", "#a78bfa", "#fb923c", "#4ade80", "#e879f9", "#2dd4bf", "#c084fc"];
let catalog = null;
function toolColor(tool) {
  const keys = catalog ? Object.keys(catalog.presets) : [];
  let i = keys.indexOf(tool);
  if (i < 0) i = [...String(tool)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7) % PALETTE.length;
  return PALETTE[i % PALETTE.length];
}
const toolName = (tool) => catalog?.presets[tool]?.name || tool;
// Custom tools are shown by the name the analyst gave them ("CrowdStrike Falcon"), not "Custom tool".
const integrationNames = new Map();
const toolBadge = (tool, integrationId) => {
  const name = tool === "custom" && integrationNames.has(integrationId) ? integrationNames.get(integrationId) : toolName(tool);
  return h("span", { class: "toolbadge", style: `--c:${toolColor(tool)}` }, name);
};
async function refreshIntegrationNames() {
  for (const i of await api("/api/integrations")) integrationNames.set(i.id, i.name);
}

// ---------- tabs ----------
let current = "overview";
function showTab(name) {
  current = name;
  $$(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  $$(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${name}`));
  if (location.hash.slice(1) !== name) history.replaceState(null, "", `#${name}`);
  loaders[name]?.();
}
$$(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

// ---------- charts ----------
const charts = {};
function chart(id, config) {
  charts[id]?.destroy();
  Chart.defaults.color = css("--muted");
  Chart.defaults.borderColor = css("--border");
  Chart.defaults.font.family = "Inter, system-ui, sans-serif";
  charts[id] = new Chart($(`#${id}`), config);
}
const levelColor = (l) => css(`--${l}`);

function histogramChart(id, hist, { legend = true } = {}) {
  const labels = [];
  for (let i = 0; i < hist.buckets; i++) {
    const t = new Date((hist.start + i * hist.step) * 1000);
    labels.push(hist.step >= 86400 ? t.toLocaleDateString(undefined, { month: "short", day: "numeric" })
      : t.toLocaleString(undefined, { hour: "2-digit", minute: "2-digit", ...(hist.step >= 3600 ? { day: "numeric" } : {}) }));
  }
  chart(id, {
    type: "bar",
    data: { labels, datasets: Object.entries(hist.series).map(([tool, data]) => ({ label: toolName(tool), data, backgroundColor: toolColor(tool), stack: "s", borderRadius: 1 })) },
    options: { maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: legend, position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } },
      scales: { x: { stacked: true, ticks: { maxTicksLimit: 10, font: { size: 11 } }, grid: { display: false } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } },
  });
}

// ---------- shared events table ----------
function netCell(e) {
  if (!e.src_ip && !e.dst_ip) return "—";
  return `${e.src_ip || "?"} → ${e.dst_ip || "?"}`;
}
function eventsTable(table, items, { append = false } = {}) {
  const rows = items.map((e) => h("tr", { on: { click: () => openEvent(e.id) } }, [
    h("td", { class: "nowrap muted small", title: e.timestamp }, fmtTime(e.timestamp)),
    h("td", {}, toolBadge(e.tool, e.integration_id)),
    h("td", { class: "nowrap" }, e.host),
    h("td", {}, pill(e.risk_score, e.risk_level)),
    h("td", { class: "msg" }, e.message),
    h("td", { class: "net" }, netCell(e)),
    h("td", { class: "nowrap small" }, e.user || ""),
  ]));
  if (append && table.tBodies[0]) { table.tBodies[0].append(...rows); return; }
  table.replaceChildren(
    h("thead", {}, h("tr", {}, ["Time", "Tool", "Host", "Risk", "Message", "Source → Destination", "User"].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: 7, class: "muted" }, "No logs match."))),
  );
}

// ---------- overview ----------
async function loadOverview() {
  const s = await api("/api/summary");
  const k = s.kpis;
  $("#health").replaceChildren(...s.integrations.map((i) => {
    const state = !i.enabled ? "off" : i.last_status === "error" ? "error" : (i.last_status || i.listening) ? "" : "wait";
    return h("button", { class: "chip", title: i.last_error || "", on: { click: () => showTab("integrations") } }, [
      h("span", { class: `dot ${state}` }), toolBadge(i.tool, i.id),
      i.name.replace(/ \(demo\)$/, "") !== toolName(i.tool) ? h("span", {}, i.name) : "",
      h("span", { class: "muted" }, `${i.events}`)]);
  }));
  $("#kpis").replaceChildren(...[
    ["Events (24h)", k.events_24h, "info"], ["Tools connected", k.tools, ""], ["Integrations healthy", `${k.integrations_ok}/${k.integrations}`, ""],
    ["Critical", k.critical, "critical"], ["High", k.high, "high"], ["Hosts", k.hosts, ""],
  ].map(([t, v, c]) => h("div", { class: `kpi ${c}` }, [h("b", {}, String(v)), h("span", {}, t)])));

  histogramChart("chart-timeline", s.timeline);
  chart("chart-tools", {
    type: "doughnut",
    data: { labels: s.by_tool.map(([t]) => toolName(t)), datasets: [{ data: s.by_tool.map(([, n]) => n), backgroundColor: s.by_tool.map(([t]) => toolColor(t)), borderWidth: 0 }] },
    options: { maintainAspectRatio: false, cutout: "58%", plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } },
      onClick: (_, els) => els.length && explore({ tools: [s.by_tool[els[0].index][0]] }) },
  });
  chart("chart-categories", {
    type: "bar",
    data: { labels: s.categories.map(([c]) => label(c)), datasets: [{ data: s.categories.map(([, n]) => n), backgroundColor: css("--accent"), borderRadius: 4 }] },
    options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true }, y: { grid: { display: false } } },
      onClick: (_, els) => els.length && explore({ category: s.categories[els[0].index][0] }) },
  });
  $("#top-hosts").replaceChildren(...(s.top_hosts.length ? s.top_hosts.map((r) =>
    h("div", { class: "host-row", on: { click: () => explore({ q: `host:${r.host}` }) } }, [
      h("b", {}, r.host), bar(r.risk_score, levelColor(r.risk_level)), pill(r.risk_score, r.risk_level)])) : [h("p", { class: "muted" }, "Nothing risky yet.")]));
  $("#top-sources").replaceChildren(...(s.top_sources.length ? s.top_sources.map(([ip, n]) =>
    h("div", { class: "ip-row", title: "Show every log involving this IP, from every tool", on: { click: () => explore({ q: `ip:${ip}`, range: "7d", sort: "time" }) } }, [
      h("span", {}, ip), h("span", { class: "muted" }, `${n} event${n === 1 ? "" : "s"} →`)])) : [h("p", { class: "muted" }, "No suspicious external IPs.")]));
  eventsTable($("#top-events"), s.top_events);
}

// ---------- log explorer ----------
const ex = { tools: new Set(), levels: new Set(), host: "", category: "", offset: 0, limit: 100, total: 0 };

function explore({ q = "", range = null, sort = null, tools = [], levels = [], host = "", category = "" } = {}) {
  $("#q").value = q;
  if (range) $("#range").value = range;
  if (sort) $("#sort").value = sort;
  ex.tools = new Set(tools);
  ex.levels = new Set(levels);
  ex.host = host;
  ex.category = category;
  showTab("explorer");
}

function explorerParams() {
  const p = new URLSearchParams({ range: $("#range").value });
  const q = $("#q").value.trim();
  if (q) p.set("q", q);
  if (ex.tools.size) p.set("tool", [...ex.tools].join(","));
  if (ex.levels.size) p.set("level", [...ex.levels].join(","));
  if (ex.host) p.set("host", ex.host);
  if (ex.category) p.set("category", ex.category);
  return p;
}

async function loadExplorer({ more = false } = {}) {
  const p = explorerParams();
  ex.offset = more ? ex.offset + ex.limit : 0;
  const listParams = new URLSearchParams(p);
  listParams.set("sort", $("#sort").value);
  listParams.set("limit", ex.limit);
  listParams.set("offset", ex.offset);
  const [list, stats] = await Promise.all([
    api(`/api/events?${listParams}`),
    more ? null : api(`/api/events/stats?${p}`),
  ]);
  ex.total = list.total;
  eventsTable($("#events-table"), list.items, { append: more });
  const shown = Math.min(ex.offset + list.items.length, list.total);
  $("#result-count").textContent = `${list.total.toLocaleString()} logs${list.total ? ` · showing ${shown.toLocaleString()}` : ""}`;
  $("#load-more").hidden = shown >= list.total;
  $("#export-csv").href = `/api/events/export?${p}&format=csv`;
  $("#export-ndjson").href = `/api/events/export?${p}&format=ndjson`;
  if (stats) {
    histogramChart("chart-histogram", stats.histogram, { legend: false });
    renderFacets(stats.facets);
  }
  renderActiveFilters();
}

function renderFacets(f) {
  const checkList = (title, items, set, render) => h("div", { class: "facet" }, [
    h("h4", {}, title),
    ...(items.length ? items.map(([key, n]) => h("label", {}, [
      h("input", { type: "checkbox", checked: set.has(key), on: { change: (e) => { e.target.checked ? set.add(key) : set.delete(key); loadExplorer(); } } }),
      h("span", { class: "name" }, render(key)), h("span", { class: "n" }, n.toLocaleString())])) : [h("span", { class: "muted small" }, "—")]),
  ]);
  const linkList = (title, items, key) => h("div", { class: "facet" }, [
    h("h4", {}, title),
    ...items.slice(0, 12).map(([value, n]) => h("div", { class: `link ${ex[key] === value ? "on" : ""}`, on: { click: () => { ex[key] = ex[key] === value ? "" : value; loadExplorer(); } } }, [
      h("span", { class: "name" }, label(value)), h("span", { class: "n" }, n.toLocaleString())])),
  ]);
  $("#facets").replaceChildren(
    checkList("Tools", f.tool, ex.tools, (t) => t === "custom" ? h("span", { class: "toolbadge", style: `--c:${toolColor(t)}` }, "Custom tools") : toolBadge(t)),
    checkList("Risk level", f.level, ex.levels, (l) => h("span", { class: l }, label(l))),
    linkList("Hosts", f.host, "host"),
    linkList("Categories", f.category, "category"),
  );
}

function renderActiveFilters() {
  const chips = [];
  for (const t of ex.tools) chips.push([`tool: ${toolName(t)}`, () => ex.tools.delete(t)]);
  for (const l of ex.levels) chips.push([`level: ${l}`, () => ex.levels.delete(l)]);
  if (ex.host) chips.push([`host: ${ex.host}`, () => (ex.host = "")]);
  if (ex.category) chips.push([`category: ${label(ex.category)}`, () => (ex.category = "")]);
  $("#active-filters").replaceChildren(...chips.map(([text, clear]) =>
    h("button", { type: "button", title: "Remove filter", on: { click: () => { clear(); loadExplorer(); } } }, `${text} ✕`)));
}

$("#querybar").addEventListener("submit", (e) => { e.preventDefault(); loadExplorer(); });
$("#range").addEventListener("change", () => loadExplorer());
$("#sort").addEventListener("change", () => loadExplorer());
$("#load-more").addEventListener("click", () => loadExplorer({ more: true }));
$("#q-help-btn").addEventListener("click", () => ($("#q-help").hidden = !$("#q-help").hidden));
setInterval(() => { if (current === "explorer" && $("#live").checked && !document.hidden) loaders.explorer(); }, 10_000);

// ---------- event drawer ----------
const FACTORS = { tactic: "MITRE tactic danger", asset: "Asset criticality", rarity: "Rule rarity", anomaly: "Volume anomaly" };

async function openEvent(id) {
  const e = await api(`/api/events/${id}`);
  const f = e.risk_factors || {};
  const pivot = (text, query) => h("button", { class: "btn ghost tiny", on: { click: () => { closeAll(); explore({ q: query, range: "7d" }); } } }, text);
  const triage = ["open", "acknowledged", "closed", "false_positive"].map((st) =>
    h("button", { class: "btn ghost tiny", "aria-pressed": String(e.status === st), on: { click: async () => {
      await api(`/api/events/${id}`, { method: "PATCH", body: JSON.stringify({ status: st }) });
      toast(`Marked as ${label(st)}`);
      openEvent(id);
    } } }, label(st)));

  $("#drawer-body").replaceChildren(
    h("div", {}, [pill(e.risk_score, e.risk_level), " ", h("span", { class: `pill ${e.risk_level}` }, e.risk_level), " ", toolBadge(e.tool, e.integration_id)]),
    h("h2", { style: "margin-top:10px" }, e.message),
    h("p", { class: "muted small" }, `${fmtTime(e.timestamp)} · via ${e.integration || "deleted integration"}${e.rule ? ` · rule ${e.rule}` : ""}`),
    h("h3", {}, "Pivot: every tool's logs for…"),
    h("div", { class: "pivots" }, [
      pivot(`host ${e.host}`, `host:${e.host}`),
      e.src_ip && pivot(`IP ${e.src_ip}`, `ip:${e.src_ip}`),
      e.dst_ip && pivot(`IP ${e.dst_ip}`, `ip:${e.dst_ip}`),
      e.user && pivot(`user ${e.user}`, `user:${e.user}`),
      e.mitre_technique && pivot(`technique ${e.mitre_technique}`, `technique:${e.mitre_technique}`),
    ]),
    h("h3", {}, "Triage"),
    h("div", { class: "status-actions" }, triage),
    h("dl", { class: "kv" }, [
      ["Host", e.host], ["Category", label(e.category)], ["Severity", `${e.severity}/100 (as reported by the tool)`], ["Source IP", e.src_ip],
      ["Destination IP", e.dst_ip], ["User", e.user], ["Action", e.action], ["MITRE tactic", e.mitre_tactic], ["MITRE technique", e.mitre_technique],
    ].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v || "—")])),
    h("h3", {}, "Why this risk score"),
    h("div", { class: "formula" }, [
      `base = severity ${f.severity} × dampener ${f.dampener} = ${(f.severity * f.dampener).toFixed(1)}`, h("br"),
      `boost = 1 − Π(1 − signal) = ${f.context_boost}`, h("br"),
      `risk = base + (100 − base) × boost × base/100 = ${e.risk_score}`,
    ]),
    h("div", { class: "factors" }, Object.entries(FACTORS).map(([key, name]) => h("div", { class: "factor" }, [
      h("span", {}, name), bar((f[key] || 0) / 0.5 * 100, css("--accent")), h("span", { class: "mono" }, `+${Math.round((f[key] || 0) * 100)}%`)]))),
    f.anomaly_z > 0 ? h("p", { class: "muted small" }, `This host's log volume in that hour was ${f.anomaly_z}σ above its own baseline.`) : "",
    h("h3", {}, "Original log"),
    h("pre", { class: "raw" }, JSON.stringify(e.raw, null, 2)),
  );
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  $("#scrim").classList.add("open");
}
function closeAll() {
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#scrim").classList.remove("open");
}
$("#scrim").addEventListener("click", closeAll);
document.addEventListener("click", (e) => {
  const c = e.target.closest("[data-close]");
  if (!c) return;
  if (c.dataset.close === "drawer") closeAll();
  if (c.dataset.close === "dialog") $("#connect-dialog").close();
});
document.addEventListener("keydown", (e) => e.key === "Escape" && closeAll());

// ---------- integrations ----------
let integrations = [];
async function loadIntegrations() {
  integrations = await api("/api/integrations");
  for (const i of integrations) integrationNames.set(i.id, i.name);
  $("#integrations").replaceChildren(...integrations.map(integrationCard));
}

function copyField(text) {
  return h("div", { class: "copy" }, [h("code", { title: text }, text),
    h("button", { class: "btn ghost tiny", on: { click: async () => { await navigator.clipboard.writeText(text); toast("Copied"); } } }, "Copy")]);
}

function integrationCard(i) {
  const type = catalog.types[i.type];
  const state = !i.enabled ? ["off", "Disabled"] : i.last_status === "error" ? ["error", "Error"]
    : i.type === "syslog" && !i.demo ? (i.listening ? ["", `Listening on ${i.config.protocol || "udp"}/${i.config.port}`] : ["error", "Not listening"])
      : i.last_status === "ok" ? ["", `Last data ${ago(i.last_run_at)}`] : ["wait", i.mode === "push" ? "Waiting for first data" : "Not pulled yet"];
  const host = location.hostname === "localhost" || location.hostname === "127.0.0.1" ? "<this server's IP>" : location.hostname;
  const act = (text, fn, cls = "btn ghost tiny") => h("button", { class: cls, on: { click: fn } }, text);

  return h("article", { class: `integration ${i.enabled ? "" : "disabled"}`, style: `--c:${toolColor(i.tool)}` }, [
    h("header", {}, [
      h("div", {}, [h("b", {}, i.name), h("span", { class: "muted small" }, `${i.preset_name} · ${i.kind}`)]),
      h("div", { class: "meta" }, [i.demo ? h("span", { class: "badge demo", title: "Fed by the built-in simulator" }, "demo") : "", h("span", { class: "badge" }, type.label.split(" (")[0])]),
    ]),
    h("div", { class: "status" }, [h("span", { class: `dot ${state[0]}` }), state[1], h("span", {}, "·"), `${i.events.toLocaleString()} events`]),
    i.last_status === "error" && i.last_error ? h("div", { class: "err" }, i.last_error) : "",
    i.webhook_url ? h("div", {}, [h("div", { class: "muted small" }, "Send logs (POST JSON / NDJSON / text) to:"), copyField(i.webhook_url)]) : "",
    i.type === "syslog" && !i.demo ? h("div", { class: "muted small" }, `Point the tool's syslog output at ${host}:${i.config.port} (${(i.config.protocol || "udp").toUpperCase()})`) : "",
    i.mode === "pull" && !i.demo && i.config.url ? h("div", { class: "muted small mono" }, i.config.url) : "",
    i.mode === "pull" && !i.demo && i.config.path ? h("div", { class: "muted small mono" }, i.config.path) : "",
    h("div", { class: "actions" }, [
      (i.mode === "pull" || i.demo) && i.enabled ? act("Pull now", async () => {
        const r = await api(`/api/integrations/${i.id}/pull`, { method: "POST" });
        toast(r.status === "error" ? `Failed: ${r.error}` : `Stored ${r.stored} events`);
        loadIntegrations();
      }) : "",
      act("Explore logs", () => explore({ tools: [i.tool], range: "7d" })),
      i.demo ? "" : act("Edit", () => openConnect(i)),
      act(i.enabled ? "Disable" : "Enable", async () => {
        await api(`/api/integrations/${i.id}/enabled?enabled=${!i.enabled}`, { method: "POST" });
        loadIntegrations();
      }),
      i.webhook_url ? act("New URL", async () => {
        if (!confirm("Generate a new webhook URL? The old one stops working immediately.")) return;
        await api(`/api/integrations/${i.id}/rotate-token`, { method: "POST" });
        toast("New webhook URL generated");
        loadIntegrations();
      }) : "",
      act("Delete", async () => {
        if (!confirm(`Delete the integration "${i.name}"?`)) return;
        const purge = i.events > 0 && confirm(`Also delete its ${i.events} stored events?\n\nOK = delete them · Cancel = keep them in the explorer`);
        await api(`/api/integrations/${i.id}?purge=${purge}`, { method: "DELETE" });
        toast("Integration deleted");
        loadIntegrations();
      }),
    ]),
  ]);
}

// ---------- connect-a-tool wizard ----------
function openConnect(existing = null) {
  const dlg = $("#connect-dialog");
  if (existing) renderForm(existing.tool, existing);
  else renderTiles();
  if (!dlg.open) dlg.showModal();
}
$$('[data-action="connect"]').forEach((b) => b.addEventListener("click", () => openConnect()));

function renderTiles() {
  const presets = Object.entries(catalog.presets);
  $("#connect-body").replaceChildren(
    h("h2", {}, "Connect a SOC tool"),
    h("p", { class: "muted" }, "Pick a preset, or choose Custom tool to connect anything that has an API, a webhook, syslog output or a log file."),
    h("div", { class: "tiles" }, presets.map(([key, p]) => h("button", { class: `tile ${key === "custom" ? "custom" : ""}`, style: `--c:${toolColor(key)}`, on: { click: () => renderForm(key) } }, [
      h("b", {}, p.name), h("span", {}, `${p.kind} · ${catalog.types[p.type].label.split(" (")[0]}`)]))),
  );
}

function fieldVisible(spec, values) {
  return Object.entries(spec.show_if || {}).every(([k, v]) => [].concat(v).includes(values[k]));
}

function renderForm(toolKey, existing = null) {
  const preset = catalog.presets[toolKey];
  let type = existing?.type || preset.type;
  const cfg = { ...(existing ? existing.config : preset.config) };
  const mapping = { ...(existing ? existing.mapping : preset.mapping) };
  const secretsSet = new Set(existing?.config?._secrets_set || []);
  const body = $("#connect-body");

  const nameInput = h("input", { name: "name", value: existing?.name || preset.name, maxlength: 120 });
  const typeSelect = h("select", { name: "type" }, Object.entries(catalog.types).map(([k, t]) => h("option", { value: k, selected: k === type }, t.label)));
  const scaleSelect = h("select", { name: "severity_scale" }, Object.entries(catalog.severity_scales).map(([k, t]) =>
    h("option", { value: k, selected: k === (existing?.severity_scale || preset.severity_scale || "auto") }, t)));
  const catSelect = h("select", { name: "default_category" }, [h("option", { value: "" }, "— none —"), ...catalog.categories.map((c) =>
    h("option", { value: c, selected: c === (existing?.default_category || preset.default_category) }, label(c)))]);
  const fieldsBox = h("div", { class: "form-grid" });
  const mapInputs = {};
  const mapBox = h("div", { class: "mapping" }, catalog.unified_fields.flatMap((f) => {
    mapInputs[f] = h("input", { value: mapping[f] || "", placeholder: "auto-detect", spellcheck: "false" });
    return [h("span", {}, f), mapInputs[f]];
  }));
  const sample = h("textarea", { placeholder: "Paste one or more log lines / a JSON payload from the tool" });
  const preview = h("div", { class: "preview" });
  const saveBtn = h("button", { class: "btn", type: "button" }, existing ? "Save changes" : "Save & connect");

  function renderFields() {
    const specs = catalog.types[type].fields;
    const values = () => Object.fromEntries(specs.map((s) => [s.key, cfg[s.key] ?? s.default]));
    fieldsBox.replaceChildren(...specs.filter((s) => fieldVisible(s, values())).map((s) => {
      let input;
      const v = cfg[s.key] ?? s.default ?? "";
      if (s.choices) input = h("select", {}, s.choices.map((c) => h("option", { value: c, selected: c === v }, c)));
      else if (s.type === "bool") input = h("input", { type: "checkbox", checked: v === true || v === "true" });
      else input = h("input", { type: s.secret ? "password" : s.type === "int" ? "number" : "text", value: s.secret ? "" : v,
        placeholder: s.secret && secretsSet.has(s.key) ? "•••••• stored — leave blank to keep" : s.placeholder || "", autocomplete: "off", spellcheck: "false" });
      const update = () => { cfg[s.key] = s.type === "bool" ? input.checked : input.value; if (s.choices) renderFields(); };
      input.addEventListener(s.choices ? "change" : "input", update);
      if (s.type === "bool") return h("label", { class: "check full" }, [input, s.label]);
      return h("label", { class: s.key === "url" || s.key === "path" || s.key === "query" || s.key === "search" ? "full" : "" }, [s.label + (s.required ? " *" : ""), input]);
    }));
  }
  typeSelect.addEventListener("change", () => { type = typeSelect.value; renderFields(); });
  renderFields();

  function payload() {
    const specs = catalog.types[type].fields;
    const config = {};
    for (const s of specs) if (cfg[s.key] !== undefined && cfg[s.key] !== "") config[s.key] = cfg[s.key];
    return {
      name: nameInput.value, tool: toolKey, type, config,
      mapping: Object.fromEntries(Object.entries(mapInputs).map(([k, i]) => [k, i.value.trim()]).filter(([, v]) => v)),
      severity_scale: scaleSelect.value, default_category: catSelect.value || null, enabled: existing ? existing.enabled : true,
    };
  }

  async function test() {
    preview.replaceChildren(h("p", { class: "muted" }, "Testing…"));
    try {
      const r = await api("/api/integrations/test", { method: "POST", body: JSON.stringify({ ...payload(), integration_id: existing?.id || null, sample: sample.value }) });
      if (!r.ok) { preview.replaceChildren(h("p", { class: "bad" }, `✕ ${r.error}`)); return; }
      if (!r.records.length) { preview.replaceChildren(h("p", { class: "ok" }, `✓ ${r.message}`)); return; }
      const cell = (ev, tr, key, value) => h("td", {}, [value ?? "—", tr && tr[key] ? h("span", { class: "from" }, `from ${tr[key]}`) : ""]);
      preview.replaceChildren(
        h("p", { class: "ok" }, r.source === "live" ? `✓ Connected — ${r.records.length} recent record(s), mapped like this:` : `✓ Sample parsed — ${r.records.length} record(s), mapped like this:`),
        h("div", { class: "table-wrap" }, h("table", {}, [
          h("thead", {}, h("tr", {}, ["Time", "Host", "Severity", "Message", "Source IP", "User", "Category"].map((t) => h("th", {}, t)))),
          h("tbody", {}, r.records.map((x) => x.error ? h("tr", {}, h("td", { colspan: 7, class: "bad" }, x.error)) : h("tr", {}, [
            cell(x.event, x.trace, "timestamp", fmtTime(x.event.timestamp)), cell(x.event, x.trace, "host", x.event.host),
            cell(x.event, x.trace, "severity", `${x.event.severity} (${x.event.risk_level})`), cell(x.event, x.trace, "message", x.event.message),
            cell(x.event, x.trace, "src_ip", x.event.src_ip), cell(x.event, x.trace, "user", x.event.user), cell(x.event, null, "", label(x.event.category)),
          ]))),
        ])),
        h("p", { class: "muted small" }, "Not right? Adjust the field mapping and test again."),
      );
    } catch (err) {
      preview.replaceChildren(h("p", { class: "bad" }, `✕ ${err.message}`));
    }
  }

  saveBtn.addEventListener("click", async () => {
    saveBtn.disabled = true;
    try {
      const saved = await api(existing ? `/api/integrations/${existing.id}` : "/api/integrations",
        { method: existing ? "PUT" : "POST", body: JSON.stringify(payload()) });
      integrationNames.set(saved.id, saved.name);
      loadIntegrations();
      renderSaved(saved, !existing);
    } catch (err) {
      preview.replaceChildren(h("p", { class: "bad" }, `✕ Could not save: ${err.message}`));
    } finally {
      saveBtn.disabled = false;
    }
  });

  body.replaceChildren(
    h("h2", {}, existing ? `Edit ${existing.name}` : `Connect ${preset.name}`),
    h("div", { class: "help" }, preset.help),
    h("div", { class: "form-grid" }, [
      h("label", {}, ["Name", nameInput]),
      h("label", {}, ["How the tool shares logs", typeSelect]),
    ]),
    h("h3", { style: "margin-top:16px" }, "Connection"),
    fieldsBox,
    h("details", { class: "box" }, [
      h("summary", {}, "Field mapping & severity"),
      h("p", { class: "muted small" }, [
        "Where each unified field lives in this tool's logs. Use dotted paths (", h("code", {}, "rule.level"), "), alternatives (",
        h("code", {}, "user.name|username"), "), templates (", h("code", {}, "{action} {srcip}"), ") or ", h("code", {}, "@asset"),
        " to name the internal host from its IPs. Leave blank to auto-detect."]),
      h("div", { class: "form-grid" }, [h("label", {}, ["Severity scale", scaleSelect]), h("label", {}, ["Default category", catSelect])]),
      mapBox,
    ]),
    h("div", { class: "stack", style: "margin-top:14px" }, [h("label", {}, [
      catalog.types[type].mode === "push" ? "Sample log (paste one to preview the mapping)" : "Sample log (optional: test without connecting)", sample])]),
    preview,
    h("div", { class: "modal-actions" }, [
      existing ? "" : h("button", { class: "btn ghost", type: "button", on: { click: renderTiles } }, "← Back"),
      h("button", { class: "btn ghost", type: "button", on: { click: test } }, "Test & preview"),
      saveBtn,
    ]),
  );
}

function renderSaved(i, isNew) {
  const host = location.hostname === "localhost" || location.hostname === "127.0.0.1" ? "<this server's IP>" : location.hostname;
  $("#connect-body").replaceChildren(
    h("h2", {}, isNew ? `✓ ${i.name} connected` : `✓ ${i.name} saved`),
    i.webhook_url ? h("div", {}, [h("p", {}, "Configure the tool to send its logs (HTTP POST) to this URL. Keep it secret: it works without a password."), copyField(i.webhook_url)]) : "",
    i.type === "syslog" ? h("p", {}, i.listening ? `Listening. Point the tool's syslog output at ${host}:${i.config.port} (${(i.config.protocol || "udp").toUpperCase()}).`
      : `Saved, but not listening: ${i.last_error || "check the port"}`) : "",
    i.mode === "pull" ? h("p", { class: i.last_status === "error" ? "bad" : "ok" },
      i.last_status === "error" ? `First pull failed: ${i.last_error}` : `First pull stored ${i.last_count} events. CyberUnify keeps pulling automatically.`) : "",
    h("div", { class: "modal-actions" }, [
      h("button", { class: "btn ghost", type: "button", on: { click: () => { $("#connect-dialog").close(); explore({ tools: [i.tool], range: "7d" }); } } }, "Explore its logs"),
      h("button", { class: "btn", type: "button", on: { click: () => { $("#connect-dialog").close(); showTab("integrations"); } } }, "Done"),
    ]),
  );
}

// ---------- hosts ----------
async function loadHosts() {
  const rows = await api("/api/hosts");
  $("#hosts-table").replaceChildren(
    h("thead", {}, h("tr", {}, ["Host", "Risk", "", "Events", "Critical", "High", "Worst finding", "Seen by", "Last seen"].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.length ? rows.map((r) => h("tr", { on: { click: () => explore({ q: `host:${r.host}`, range: "7d" }) } }, [
      h("td", {}, h("b", {}, r.host)), h("td", {}, pill(r.risk_score, r.risk_level)), h("td", { style: "width:16%" }, bar(r.risk_score, levelColor(r.risk_level))),
      h("td", {}, String(r.alerts)), h("td", { class: "critical" }, String(r.critical)), h("td", { class: "high" }, String(r.high)),
      h("td", { class: "msg" }, r.top_alert), h("td", {}, h("div", { class: "pivots", style: "margin:0" }, r.tools.map(toolBadge))),
      h("td", { class: "muted nowrap" }, ago(r.last_seen)),
    ])) : h("tr", {}, h("td", { colspan: 9, class: "muted" }, "No risky activity."))),
  );
}

// ---------- compliance ----------
async function loadCompliance() {
  const r = await api("/api/compliance");
  const s = r.summary;
  $("#posture").replaceChildren(
    h("div", { class: "score" }, `${s.posture_score}%`),
    h("div", {}, [
      h("b", {}, r.framework), h("div", { class: "muted small" }, "Share of assessed controls currently effective, from every connected tool"),
      h("div", { class: "counts" }, [
        h("span", { class: "critical" }, `${s.at_risk} at risk`), h("span", { class: "high" }, `${s.needs_review} need review`),
        h("span", { class: "low" }, `${s.effective} effective`), h("span", { class: "muted" }, `${s.no_evidence} no evidence`)]),
    ]),
  );
  $("#controls").replaceChildren(...r.controls.map((c) => h("article", { class: `control s-${c.status.toLowerCase().replace(/ /g, "-")}` }, [
    h("header", {}, [h("b", {}, c.control), h("span", { class: "st" }, c.status)]),
    h("div", {}, c.name),
    c.evidence.length ? h("ul", {}, c.evidence.map((e) => h("li", {}, e))) : h("p", { class: "muted small" }, "No events mapped to this control yet."),
    c.recommendation ? h("p", { class: "rec" }, ["→ ", c.recommendation]) : "",
  ])));
}

// ---------- vendors ----------
let questionsRendered = false;
async function loadVendors() {
  const data = await api("/api/vendors");
  if (!questionsRendered) {
    $("#questions").replaceChildren(...data.questions.map((q) => h("label", { class: "q" }, [h("input", { type: "checkbox", name: `q_${q.key}` }), h("span", {}, q.text)])));
    questionsRendered = true;
  }
  const tierClass = { Critical: "critical", High: "high", Medium: "medium", Low: "low" };
  $("#vendors-table").replaceChildren(
    h("thead", {}, h("tr", {}, ["Vendor", "Data / access", "Inherent", "Controls met", "Residual", "Top gaps", ""].map((t) => h("th", {}, t)))),
    h("tbody", {}, data.items.length ? data.items.map((v) => h("tr", {}, [
      h("td", {}, [h("b", {}, v.name), h("div", { class: "muted small" }, v.service)]),
      h("td", { class: "nowrap small" }, `${v.data_sensitivity} / ${v.access_level}`),
      h("td", {}, String(Math.round(v.inherent_risk))), h("td", {}, `${Math.round(v.control_score)}%`),
      h("td", {}, h("span", { class: `pill ${tierClass[v.tier]}` }, `${Math.round(v.residual_risk)} · ${v.tier}`)),
      h("td", {}, v.gaps.length ? h("ul", { class: "gaps" }, v.gaps.slice(0, 3).map((g) => h("li", {}, g))) : h("span", { class: "muted small" }, "None")),
      h("td", {}, h("button", { class: "btn ghost tiny", on: { click: async () => {
        if (!confirm(`Remove ${v.name} from the register?`)) return;
        await api(`/api/vendors/${v.id}`, { method: "DELETE" });
        toast("Vendor removed");
        loadVendors();
      } } }, "Remove")),
    ])) : h("tr", {}, h("td", { colspan: 7, class: "muted" }, "No vendors assessed yet."))),
  );
}

$("#vendor-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const answers = {};
  $$("input[type=checkbox]", form).forEach((c) => (answers[c.name.slice(2)] = c.checked));
  const status = $("#vendor-status");
  try {
    const v = await api("/api/vendors", { method: "POST", body: JSON.stringify({
      name: form.elements.name.value, service: form.elements.service.value,
      data_sensitivity: form.elements.data_sensitivity.value, access_level: form.elements.access_level.value, answers }) });
    status.className = "small low";
    status.textContent = `${v.name}: residual risk ${Math.round(v.residual_risk)} (${v.tier})`;
    form.reset();
    loadVendors();
  } catch (err) {
    status.className = "small critical";
    status.textContent = `Could not save: ${err.message}`;
  }
});

// ---------- boot ----------
const loaders = { overview: loadOverview, explorer: loadExplorer, integrations: loadIntegrations, hosts: loadHosts, compliance: loadCompliance, vendors: loadVendors };
for (const k of Object.keys(loaders)) {
  const fn = loaders[k];
  loaders[k] = (...args) => fn(...args).catch((err) => toast(`Error: ${err.message}`));
}
const tabFromHash = () => (location.hash.slice(1) in loaders ? location.hash.slice(1) : "overview");
window.addEventListener("hashchange", () => tabFromHash() !== current && showTab(tabFromHash()));

(async () => {
  catalog = await api("/api/catalog");
  await refreshIntegrationNames();
  showTab(tabFromHash());
  setInterval(() => { if (current === "overview" && !document.hidden) loaders.overview(); }, 30_000);
})();
