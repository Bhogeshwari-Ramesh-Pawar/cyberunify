// CyberUnify dashboard.
// Alert fields come from external tools and can contain attacker-controlled text
// (usernames, user-agents, URLs), so everything is rendered with textContent, never innerHTML.

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];

function h(tag, attrs = {}, children = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "on") for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
    else if (k === "style") n.style.cssText = v;
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of [].concat(children)) if (c != null && c !== "") n.append(c);
  return n;
}

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail ? JSON.stringify(data.detail) : `${res.status} ${res.statusText}`);
  return data;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 2600);
}

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const LEVELS = ["critical", "high", "medium", "low"];
const fmtTime = (iso) => new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
const ago = (iso) => {
  const m = Math.round((Date.now() - new Date(iso)) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  if (m < 1440) return `${Math.round(m / 60)}h ago`;
  return `${Math.round(m / 1440)}d ago`;
};
const label = (s) => (s || "").replace(/_/g, " ");
const pill = (score, level) => h("span", { class: `pill ${level}` }, `${Math.round(score)}`);
const bar = (pct, color) => h("div", { class: "bar" }, h("i", { style: `width:${Math.max(2, Math.min(100, pct))}%;background:${color}` }));

// ---------- tabs ----------
let current = "overview";
function showTab(name) {
  current = name;
  $$(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  $$(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${name}`));
  history.replaceState(null, "", `#${name}`);
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
const levelColors = () => Object.fromEntries(LEVELS.map((l) => [l, css(`--${l}`)]));

// ---------- alerts table (shared) ----------
function alertsTable(table, items, { compact = false } = {}) {
  const head = h("thead", {}, h("tr", {}, [
    h("th", {}, "Risk"), h("th", {}, "Time"), h("th", {}, "Host"), h("th", {}, "Alert"),
    compact ? null : h("th", {}, "Category"), h("th", {}, "MITRE"), h("th", {}, "Source"), compact ? null : h("th", {}, "Status"),
  ]));
  const body = h("tbody", {}, items.length ? items.map((a) => h("tr", { on: { click: () => openAlert(a.id) } }, [
    h("td", {}, pill(a.risk_score, a.risk_level)),
    h("td", { class: "nowrap muted", title: a.timestamp }, ago(a.timestamp)),
    h("td", { class: "nowrap" }, a.host),
    h("td", { class: "title" }, a.title),
    compact ? null : h("td", { class: "nowrap" }, h("span", { class: "tag" }, label(a.category))),
    h("td", { class: "nowrap mono small" }, a.mitre_technique || "—"),
    h("td", {}, h("span", { class: "tag" }, a.source)),
    compact ? null : h("td", {}, h("span", { class: `status ${a.status}` }, label(a.status))),
  ])) : h("tr", {}, h("td", { colspan: 8, class: "muted" }, "No alerts match.")));
  table.replaceChildren(head, body);
}

// ---------- overview ----------
async function loadOverview() {
  const s = await api("/api/summary");
  const k = s.kpis;
  $("#kpis").replaceChildren(
    ...[
      ["Alerts", k.alerts, ""], ["Untriaged", k.open, ""], ["Critical", k.critical, "critical"],
      ["High", k.high, "high"], ["Hosts", k.hosts, ""], ["Mean risk", k.mean_risk, ""],
    ].map(([t, v, c]) => h("div", { class: `kpi ${c}` }, [h("b", {}, String(v)), h("span", {}, t)]))
  );
  renderSources(s.sources);

  const colors = levelColors();
  chart("chart-timeline", {
    type: "bar",
    data: {
      labels: s.timeline.hours.map((t) => new Date(t).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })),
      datasets: [...LEVELS].reverse().map((l) => ({ label: l, data: s.timeline.series[l], backgroundColor: colors[l], stack: "a", borderRadius: 2 })),
    },
    options: { maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } },
      scales: { x: { stacked: true, ticks: { maxTicksLimit: 12 }, grid: { display: false } }, y: { stacked: true, beginAtZero: true } } },
  });
  chart("chart-levels", {
    type: "doughnut",
    data: { labels: LEVELS, datasets: [{ data: LEVELS.map((l) => s.risk_levels[l]), backgroundColor: LEVELS.map((l) => colors[l]), borderWidth: 0 }] },
    options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } } },
  });
  chart("chart-tactics", {
    type: "bar",
    data: { labels: s.tactics.map(([t]) => t), datasets: [{ data: s.tactics.map(([, n]) => n), backgroundColor: css("--accent"), borderRadius: 4 }] },
    options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true }, y: { grid: { display: false } } } },
  });
  chart("chart-categories", {
    type: "bar",
    data: { labels: s.categories.map(([c]) => label(c)), datasets: [{ data: s.categories.map(([, n]) => n), backgroundColor: "#a78bfa", borderRadius: 4 }] },
    options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true }, y: { grid: { display: false } } } },
  });

  $("#top-hosts").replaceChildren(...(s.top_hosts.length ? s.top_hosts.map((hst) =>
    h("div", { class: "host-row", on: { click: () => filterAlerts({ host: hst.host }) } }, [
      h("b", {}, hst.host), bar(hst.risk_score, colors[hst.risk_level]), pill(hst.risk_score, hst.risk_level),
    ])) : [h("p", { class: "muted" }, "No active alerts.")]));
  alertsTable($("#top-alerts"), s.top_alerts, { compact: true });
}

function renderSources(sources) {
  $("#sources").replaceChildren(...(sources.length ? sources.map((src) =>
    h("span", { class: `source ${src.status === "ok" ? "" : "error"}`, title: src.error || "" }, [
      h("span", { class: "dot" }), h("b", {}, src.source),
      h("span", { class: "muted" }, src.status === "ok" ? `${src.fetched} alerts · ${ago(src.finished_at)}` : "error"),
    ])) : [h("span", { class: "muted small" }, "No data sources configured yet.")]));
  const last = sources.map((s) => s.finished_at).sort().pop();
  $("#last-sync").textContent = last ? `synced ${ago(last)}` : "";
}

// ---------- alerts tab ----------
let alertQuery = { offset: 0, limit: 50 };
let facetsLoaded = false;
let pendingFilter = null; // filter requested before the dropdown options exist

function applyFilter(params) {
  const form = $("#filters");
  for (const [k, v] of Object.entries(params)) if (form.elements[k]) form.elements[k].value = v;
}

function filterAlerts(params) {
  $("#filters").reset();
  pendingFilter = facetsLoaded ? null : params;
  applyFilter(params);
  alertQuery.offset = 0;
  showTab("alerts");
}

async function loadAlerts() {
  const form = $("#filters");
  const params = new URLSearchParams();
  for (const el of form.elements) if (el.name && el.value) params.set(el.name, el.value);
  for (const [k, v] of Object.entries(pendingFilter || {})) params.set(k, v);
  params.set("limit", alertQuery.limit);
  params.set("offset", alertQuery.offset);
  const data = await api(`/api/alerts?${params}`);

  if (!facetsLoaded) {
    const fill = (name, values) => {
      const sel = form.elements[name];
      const chosen = sel.value;
      sel.append(...values.map((v) => h("option", { value: v }, label(v))));
      sel.value = chosen;
    };
    fill("level", data.facets.levels);
    fill("source", data.facets.sources);
    fill("host", data.facets.hosts);
    fill("category", data.facets.categories);
    fill("status", data.facets.statuses);
    facetsLoaded = true;
    if (pendingFilter) applyFilter(pendingFilter); // now the options exist, show the chosen filter
    pendingFilter = null;
  }

  alertsTable($("#alerts-table"), data.items);
  const end = Math.min(alertQuery.offset + data.items.length, data.total);
  $("#alerts-count").textContent = data.total ? `${alertQuery.offset + 1}–${end} of ${data.total} alerts` : "0 alerts";
  $("#prev").disabled = alertQuery.offset === 0;
  $("#next").disabled = end >= data.total;
}

let debounce;
$("#filters").addEventListener("input", () => {
  clearTimeout(debounce);
  debounce = setTimeout(() => { alertQuery.offset = 0; loadAlerts(); }, 250);
});
$("#filters").addEventListener("submit", (e) => e.preventDefault());
$("#prev").addEventListener("click", () => { alertQuery.offset = Math.max(0, alertQuery.offset - alertQuery.limit); loadAlerts(); });
$("#next").addEventListener("click", () => { alertQuery.offset += alertQuery.limit; loadAlerts(); });

// ---------- alert drawer ----------
const FACTOR_INFO = {
  tactic: "MITRE tactic danger",
  asset: "Asset criticality",
  rarity: "Rule rarity",
  anomaly: "Volume anomaly",
};

async function openAlert(id) {
  const a = await api(`/api/alerts/${id}`);
  const f = a.risk_factors || {};
  const statusBtns = ["open", "acknowledged", "closed", "false_positive"].map((st) =>
    h("button", { class: "btn ghost tiny", "aria-pressed": String(a.status === st), on: { click: async () => {
      await api(`/api/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status: st }) });
      toast(`Marked as ${label(st)}`);
      openAlert(id);
      loaders[current]?.();
    } } }, label(st)));

  $("#drawer-body").replaceChildren(
    h("div", {}, [pill(a.risk_score, a.risk_level), " ", h("span", { class: `pill ${a.risk_level}` }, a.risk_level)]),
    h("h2", {}, a.title),
    h("p", { class: "muted small" }, `${fmtTime(a.timestamp)} · ${a.source} · rule ${a.rule_id}`),
    h("h3", {}, "Triage"),
    h("div", { class: "status-actions" }, statusBtns),
    h("dl", { class: "kv" }, [
      ["Host", a.host], ["Category", label(a.category)], ["Source IP", a.src_ip], ["Destination IP", a.dst_ip],
      ["User", a.user], ["MITRE tactic", a.mitre_tactic], ["MITRE technique", a.mitre_technique],
    ].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v || "—")])),
    h("h3", {}, "Why this score"),
    h("div", { class: "formula" }, [
      `base = severity ${f.severity} × dampener ${f.dampener} = ${(f.severity * f.dampener).toFixed(1)}`, h("br"),
      `boost = 1 − Π(1 − signal) = ${f.context_boost}`, h("br"),
      `risk = base + (100 − base) × boost × base/100 = ${a.risk_score}`,
    ]),
    h("div", { class: "factors" }, Object.entries(FACTOR_INFO).map(([key, name]) =>
      h("div", { class: "factor" }, [
        h("span", {}, name), bar((f[key] || 0) / 0.5 * 100, css("--accent")),
        h("span", { class: "mono" }, `+${Math.round((f[key] || 0) * 100)}%`),
      ]))),
    f.anomaly_z > 0 ? h("p", { class: "muted small" }, `This host's alert volume in that hour was ${f.anomaly_z}σ above its own baseline.`) : "",
    h("h3", {}, "Raw event"),
    h("pre", { class: "raw" }, JSON.stringify(a.raw, null, 2)),
  );
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  $("#scrim").classList.add("open");
}
function closeDrawer() {
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#scrim").classList.remove("open");
}
$("#drawer-close").addEventListener("click", closeDrawer);
$("#scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => e.key === "Escape" && closeDrawer());

// ---------- hosts ----------
async function loadHosts() {
  const rows = await api("/api/hosts");
  const colors = levelColors();
  $("#hosts-table").replaceChildren(
    h("thead", {}, h("tr", {}, ["Host", "Risk", "", "Alerts", "Critical", "High", "Worst finding", "Sources", "Last seen"].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.length ? rows.map((r) => h("tr", { on: { click: () => filterAlerts({ host: r.host }) } }, [
      h("td", {}, h("b", {}, r.host)), h("td", {}, pill(r.risk_score, r.risk_level)), h("td", { style: "width:20%" }, bar(r.risk_score, colors[r.risk_level])),
      h("td", {}, String(r.alerts)), h("td", { class: "critical" }, String(r.critical)), h("td", { class: "high" }, String(r.high)),
      h("td", { class: "title" }, r.top_alert), h("td", {}, r.sources.map((s) => h("span", { class: "tag" }, s))),
      h("td", { class: "muted nowrap" }, ago(r.last_seen)),
    ])) : h("tr", {}, h("td", { colspan: 9, class: "muted" }, "No active alerts."))),
  );
}

// ---------- compliance ----------
async function loadCompliance() {
  const r = await api("/api/compliance");
  const s = r.summary;
  $("#posture").replaceChildren(
    h("div", { class: "score" }, `${s.posture_score}%`),
    h("div", {}, [
      h("b", {}, r.framework), h("div", { class: "muted small" }, "Share of assessed controls currently effective"),
      h("div", { class: "counts" }, [
        h("span", { class: "critical" }, `${s.at_risk} at risk`), h("span", { class: "high" }, `${s.needs_review} need review`),
        h("span", { class: "low" }, `${s.effective} effective`), h("span", { class: "muted" }, `${s.no_evidence} no evidence`),
      ]),
    ]),
  );
  $("#controls").replaceChildren(...r.controls.map((c) =>
    h("article", { class: `control s-${c.status.toLowerCase().replace(/ /g, "-")}` }, [
      h("header", {}, [h("b", {}, c.control), h("span", { class: "st" }, c.status)]),
      h("div", {}, c.name),
      c.evidence.length ? h("ul", {}, c.evidence.map((e) => h("li", {}, e))) : h("p", { class: "muted small" }, "No alerts mapped to this control yet."),
      c.recommendation ? h("p", { class: "rec" }, ["→ ", c.recommendation]) : "",
    ])));
}

// ---------- vendors ----------
let questionsRendered = false;
async function loadVendors() {
  const data = await api("/api/vendors");
  if (!questionsRendered) {
    $("#questions").replaceChildren(...data.questions.map((q) =>
      h("label", { class: "q" }, [h("input", { type: "checkbox", name: `q_${q.key}` }), h("span", {}, q.text)])));
    questionsRendered = true;
  }
  const tierClass = { Critical: "critical", High: "high", Medium: "medium", Low: "low" };
  $("#vendors-table").replaceChildren(
    h("thead", {}, h("tr", {}, ["Vendor", "Data / access", "Inherent", "Controls met", "Residual", "Top gaps", ""].map((t) => h("th", {}, t)))),
    h("tbody", {}, data.items.length ? data.items.map((v) => h("tr", {}, [
      h("td", {}, [h("b", {}, v.name), h("div", { class: "muted small" }, v.service)]),
      h("td", { class: "nowrap small" }, `${v.data_sensitivity} / ${v.access_level}`),
      h("td", {}, String(Math.round(v.inherent_risk))),
      h("td", {}, `${Math.round(v.control_score)}%`),
      h("td", {}, h("span", { class: `pill ${tierClass[v.tier]}` }, `${Math.round(v.residual_risk)} · ${v.tier}`)),
      h("td", {}, v.gaps.length ? h("ul", { class: "gaps" }, v.gaps.slice(0, 3).map((g) => h("li", {}, g))) : h("span", { class: "muted small" }, "None")),
      h("td", {}, h("button", { class: "btn ghost tiny", on: { click: async (e) => {
        e.stopPropagation();
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
      data_sensitivity: form.elements.data_sensitivity.value, access_level: form.elements.access_level.value, answers,
    }) });
    status.className = "small low";
    status.textContent = `${v.name}: residual risk ${Math.round(v.residual_risk)} (${v.tier})`;
    form.reset();
    loadVendors();
  } catch (err) {
    status.className = "small critical";
    status.textContent = `Could not save: ${err.message}`;
  }
});

// ---------- ingest ----------
$("#ingest-btn").addEventListener("click", async () => {
  const btn = $("#ingest-btn");
  btn.disabled = true;
  btn.textContent = "Ingesting…";
  try {
    const r = await api("/api/ingest", { method: "POST" });
    const failed = r.results.filter((x) => x.status !== "ok");
    toast(failed.length ? `Done, but ${failed.map((f) => f.source).join(", ")} failed` : `Ingested ${r.results.reduce((n, x) => n + (x.fetched || 0), 0)} alerts`);
    loaders[current]?.();
  } catch (err) {
    toast(`Ingest failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "↻ Ingest now";
  }
});

// ---------- boot ----------
const loaders = { overview: loadOverview, alerts: loadAlerts, hosts: loadHosts, compliance: loadCompliance, vendors: loadVendors };
const wrap = (fn) => () => fn().catch((err) => toast(`Error: ${err.message}`));
for (const k of Object.keys(loaders)) loaders[k] = wrap(loaders[k]);

const tabFromHash = () => (location.hash.slice(1) in loaders ? location.hash.slice(1) : "overview");
window.addEventListener("hashchange", () => tabFromHash() !== current && showTab(tabFromHash()));
showTab(tabFromHash());
setInterval(() => current === "overview" && loaders.overview(), 60_000);
