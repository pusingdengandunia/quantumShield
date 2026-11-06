"use strict";

// All scanned data is untrusted (certificate subjects, SSH banners), so the page
// builds DOM nodes with text content and never assigns innerHTML.
const KIND_LABEL = { tls: "TLS", ssh: "SSH", repo: "Kode" };
const STATUS = {
  critical: { icon: "!", label: "Rentan" },
  warning: { icon: "~", label: "Perlu tindakan" },
  good: { icon: "✓", label: "Terlindungi" },
  unknown: { icon: "?", label: "Tidak terjangkau" },
};

const $ = (id) => document.getElementById(id);
let state = null;
let openRow = null;

function h(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== false && value != null) node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child != null) node.append(child);
  }
  return node;
}

function showError(message) {
  $("error").textContent = message || "";
  $("error").hidden = !message;
}

async function api(path, method = "GET", body) {
  const response = await fetch(path, {
    method,
    headers: { "X-QShield": "1", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const detail = Array.isArray(payload.detail) ? payload.detail.map((d) => d.msg).join("; ") : payload.detail;
    throw new Error(detail || `Permintaan gagal (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

/** Disable the button while the work runs, then refresh the page data. */
async function act(button, label, work) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = label;
  showError("");
  try {
    await work();
    await refresh();
  } catch (error) {
    showError(error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function statusOf(row) {
  if (!row.reachable) return "unknown";
  if (row.assessment.risk === 0) return "good";
  return row.assessment.mosca_vulnerable ? "critical" : "warning";
}

function statusBadge(kind) {
  const css = kind === "unknown" ? "warning" : kind;
  return h("span", { class: `status status-${css}` },
    h("span", { class: "status-icon", "aria-hidden": "true" }, STATUS[kind].icon), STATUS[kind].label);
}

function formatTime(iso) {
  return new Date(iso).toLocaleString("id-ID", { dateStyle: "medium", timeStyle: "short" });
}

function renderScore(data) {
  $("score").textContent = data.readiness == null ? "–" : data.readiness.toFixed(1);
  $("summary").textContent = data.summary;
  $("scanned-at").textContent = data.scanned_at ? `Scan terakhir ${formatTime(data.scanned_at)}` : "Belum ada scan";
  const delta = $("delta");
  delta.className = "delta";
  delta.textContent = "";
  if (data.readiness != null && data.previous_readiness != null) {
    const change = data.readiness - data.previous_readiness;
    if (Math.abs(change) >= 0.05) {
      delta.classList.add(change > 0 ? "up" : "down");
      delta.textContent = `${change > 0 ? "▲ +" : "▼ "}${change.toFixed(1)} dari scan sebelumnya`;
    } else {
      delta.textContent = "Tidak berubah dari scan sebelumnya";
    }
  }
}

function svg(tag, attributes = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
  node.append(...children);
  return node;
}

function renderTrend(history) {
  const points = history.filter((scan) => scan.readiness != null);
  $("trend-figure").hidden = points.length < 2;
  const host = $("trend");
  host.replaceChildren();
  if (points.length < 2) return;

  const W = 560, H = 190, left = 34, right = 12, top = 12, bottom = 12;
  const x = (i) => left + (i / (points.length - 1)) * (W - left - right);
  const y = (value) => top + (1 - value / 100) * (H - top - bottom);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img",
    "aria-label": `Tren skor dari ${points[0].readiness} ke ${points.at(-1).readiness}` });
  for (const tick of [0, 50, 100]) {
    root.append(svg("line", { x1: left, x2: W - right, y1: y(tick), y2: y(tick), stroke: "var(--grid)" }));
    const label = svg("text", { x: left - 8, y: y(tick) + 4, "text-anchor": "end", "font-size": 11, fill: "var(--text-secondary)" });
    label.textContent = tick;
    root.append(label);
  }
  const path = points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(p.readiness).toFixed(1)}`).join("");
  root.append(svg("path", { d: path, fill: "none", stroke: "var(--series-1)", "stroke-width": 2, "stroke-linejoin": "round" }));
  const marker = svg("circle", { r: 5, fill: "var(--series-1)", stroke: "var(--surface-1)", "stroke-width": 2,
    cx: x(points.length - 1), cy: y(points.at(-1).readiness) });
  root.append(marker);

  const tooltip = h("div", { class: "tooltip", hidden: true });
  const place = (event) => {
    const box = root.getBoundingClientRect();
    const scale = W / box.width;
    const position = (event.clientX - box.left) * scale;
    const ratio = (position - left) / (W - left - right);
    const index = Math.max(0, Math.min(points.length - 1, Math.round(ratio * (points.length - 1))));
    const point = points.at(index);
    marker.setAttribute("cx", x(index));
    marker.setAttribute("cy", y(point.readiness));
    tooltip.hidden = false;
    tooltip.textContent = `${point.readiness.toFixed(1)} · ${formatTime(point.finished_at)}`;
    tooltip.style.left = `${Math.min(box.width - 80, Math.max(80, x(index) / scale))}px`;
    tooltip.style.top = `${Math.max(26, y(point.readiness) / scale - 10)}px`;
  };
  root.addEventListener("pointermove", place);
  root.addEventListener("pointerleave", () => {
    tooltip.hidden = true;
    marker.setAttribute("cx", x(points.length - 1));
    marker.setAttribute("cy", y(points.at(-1).readiness));
  });
  host.append(root, tooltip);
}

function renderKpis(kpi) {
  const tile = (label, value) => h("div", { class: "kpi" }, h("div", { class: "label" }, label), h("div", { class: "value" }, String(value)));
  $("kpis").replaceChildren(
    tile("Aset terpindai", kpi.reachable),
    tile("Rentan (teorema Mosca)", kpi.mosca_vulnerable),
    tile("Terlindungi", kpi.protected),
    tile("Temuan kritis", kpi.critical_findings),
  );
}

function factorsList(a) {
  const entry = (term, value) => [h("dt", {}, term), h("dd", {}, value)];
  return h("dl", { class: "factors" },
    entry("A algoritma", a.A.toFixed(1)),
    entry("S sensitivitas", a.S.toFixed(1)),
    entry("E eksposur", a.E.toFixed(1)),
    entry("M migrasi", a.M.toFixed(1)),
    entry("Mosca X + Y", `${a.X} + ${a.Y} = ${a.X + a.Y} tahun`),
    entry("Mosca Z", `${a.Z} tahun`),
    entry("Hasil", a.A === 0 ? "Tidak ada kerahasiaan rentan" : a.mosca_vulnerable ? "X + Y > Z: rentan HNDL" : "X + Y ≤ Z"),
    entry("Sumber X dan Y", state.settings.mosca_source || "Asumsi awal, belum ada sumber resmi"));
}

function benchmarkTable(bench) {
  const row = (name, data) => h("tr", {}, h("td", {}, name), h("td", {}, data.median_ms.toFixed(1)), h("td", {}, data.bytes.toLocaleString("id-ID")));
  const sign = bench.extra_ms >= 0 ? "+" : "";
  return h("div", {},
    h("h3", {}, `Benchmark gateway (median ${bench.classic.samples} handshake)`),
    h("table", { class: "mini" },
      h("thead", {}, h("tr", {}, h("th", {}, "Grup"), h("th", {}, "Waktu (ms)"), h("th", {}, "Data (byte)"))),
      h("tbody", {}, row(bench.classic_group, bench.classic), row(bench.hybrid_group, bench.hybrid))),
    h("p", { class: "muted" }, `Overhead hybrid: ${sign}${bench.extra_ms.toFixed(1)} ms, +${bench.extra_bytes.toLocaleString("id-ID")} byte. Waktu mencakup start proses openssl; bandingkan selisihnya.`));
}

function detailRow(row, readOnly) {
  const target = row.target;
  const actions = h("div", { class: "detail-actions" });
  if (!readOnly && target.kind === "tls" && target.migration === "gateway" && !row.detail.hybrid) {
    actions.append(h("button", { class: "button primary", type: "button", onclick: (event) => act(event.target, "Memasang…", async () => {
      await api(`api/targets/${target.id}/gateway`, "POST");
      await api("api/scans", "POST");
    }) }, "Terapkan PQC Gateway"));
  }
  if (!readOnly && target.gateway_port) {
    actions.append(h("button", { class: "button", type: "button", onclick: (event) => act(event.target, "Mengukur…", () => api(`api/targets/${target.id}/benchmark`, "POST")) }, "Jalankan benchmark"));
    actions.append(h("button", { class: "button", type: "button", onclick: (event) => act(event.target, "Melepas…", async () => {
      await api(`api/targets/${target.id}/gateway`, "DELETE");
      await api("api/scans", "POST");
    }) }, "Lepas gateway"));
  }
  const items = row.items.filter((item) => item.role !== "code");
  const codeHits = row.items.length - items.length;
  const gateway = target.gateway_port
    ? h("p", { class: "muted" }, `Gateway ${target.gateway_status || "-"} di port ${target.gateway_port}. Dari komputer ini: https://localhost:${target.gateway_port}`)
    : null;
  const findings = row.findings.length
    ? h("ul", {}, row.findings.map((finding) => h("li", { class: finding.severity === "critical" ? "finding-critical" : "" }, finding.text)))
    : h("p", { class: "muted" }, "Tidak ada temuan.");
  return h("tr", { class: "detail" }, h("td", { colspan: 5 },
    h("div", { class: "detail-grid" },
      h("div", {}, h("h3", {}, `Mengapa skornya ${row.assessment.risk.toFixed(1)}`), factorsList(row.assessment)),
      h("div", {}, h("h3", {}, "Temuan"), findings),
      h("div", {}, h("h3", {}, "Kriptografi terdeteksi"),
        items.length ? h("ul", {}, items.map((item) => h("li", {}, `${item.algorithm} (${item.role})`))) : null,
        codeHits ? h("p", {}, `${codeHits} pemakaian di ${row.detail.files_scanned} berkas.`) : null,
        row.detail.versions ? h("p", { class: "muted" }, row.detail.versions.join(", ")) : null,
        row.benchmark ? benchmarkTable(row.benchmark) : null)),
    gateway, actions));
}

function renderAssets(data) {
  const body = $("assets").tBodies[0];
  body.replaceChildren();
  if (!data.rows.length) {
    body.append(h("tr", {}, h("td", { colspan: 5, class: "muted" }, "Belum ada hasil. Daftarkan target lalu jalankan scan.")));
  }
  for (const row of data.rows) {
    const kex = row.items.find((item) => item.role === "kex");
    const fill = h("div", { class: "risk-fill" });
    fill.style.width = `${row.assessment.risk}%`;
    const toggle = () => { openRow = openRow === row.target_id ? null : row.target_id; renderAssets(state); };
    body.append(h("tr", { class: "asset", tabindex: 0, "aria-expanded": String(openRow === row.target_id), onclick: toggle,
      onkeydown: (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); toggle(); } } },
      h("td", {}, h("span", { class: "name" }, row.target_name)),
      h("td", {}, KIND_LABEL[row.target.kind]),
      h("td", {}, kex ? kex.algorithm : row.target.kind === "repo" ? `${row.items.length} temuan` : "–"),
      h("td", {}, h("div", { class: "risk" }, h("div", { class: "risk-track" }, fill), h("span", { class: "risk-number" }, row.assessment.risk.toFixed(1)))),
      h("td", {}, statusBadge(statusOf(row)))));
    if (openRow === row.target_id) body.append(detailRow(row, data.read_only));
  }
}

function renderRoadmap(entries) {
  const body = $("roadmap").tBodies[0];
  body.replaceChildren();
  if (!entries.length) {
    body.append(h("tr", {}, h("td", { colspan: 3, class: "muted" }, "Tidak ada aset yang perlu dimigrasi.")));
  }
  for (const entry of entries) {
    body.append(h("tr", {}, h("td", {}, entry.phase), h("td", {}, entry.target), h("td", {}, entry.action)));
  }
}

function fillSelect(name, options) {
  const select = $("target-form").elements[name];
  if (select.options.length) return;
  for (const [value, label] of Object.entries(options)) select.append(h("option", { value }, label));
}

function renderManage(data) {
  $("manage").hidden = data.read_only;
  $("scan-button").hidden = data.read_only;
  $("readonly-banner").hidden = !data.read_only;
  if (data.read_only) return;
  fillSelect("sensitivity", data.options.sensitivity);
  fillSelect("exposure", data.options.exposure);
  fillSelect("migration", data.options.migration);
  $("targets").replaceChildren(...data.targets.map((target) => h("li", {},
    h("span", {}, `${target.name} · ${target.kind === "repo" ? target.path : `${target.host}:${target.port}`}`),
    h("button", { class: "button", type: "button", onclick: (event) => act(event.target, "…", () => api(`api/targets/${target.id}`, "DELETE")) }, "Hapus"))));
  const form = $("settings-form");
  if (document.activeElement?.form !== form) {
    for (const [key, value] of Object.entries(data.settings)) form.elements[key].value = value;
  }
}

async function refresh() {
  state = await api("api/dashboard");
  renderScore(state);
  renderTrend(state.history);
  renderKpis(state.kpi);
  renderAssets(state);
  renderRoadmap(state.roadmap);
  renderManage(state);
}

$("scan-button").addEventListener("click", (event) => act(event.target, "Memindai…", () => api("api/scans", "POST")));

$("target-form").elements.kind.addEventListener("change", (event) => {
  const repo = event.target.value === "repo";
  for (const label of $("target-form").querySelectorAll("[data-for]")) {
    label.hidden = (label.dataset.for === "repo") !== repo;
  }
  if (event.target.value === "ssh") $("target-form").elements.port.value = 22;
  if (event.target.value === "tls") $("target-form").elements.port.value = 443;
});

$("target-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.target;
  const values = Object.fromEntries(new FormData(form));
  const body = { ...values, authorized: form.elements.authorized.checked };
  body.port = values.kind === "repo" ? null : Number(values.port);
  act(form.querySelector("button"), "Menyimpan…", async () => {
    await api("api/targets", "POST", body);
    form.reset();
    form.elements.kind.dispatchEvent(new Event("change"));
  });
});

$("settings-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.target;
  const body = Object.fromEntries([...new FormData(form)].map(([key, value]) => [key, key === "mosca_source" ? value : Number(value)]));
  act(form.querySelector("button"), "Menyimpan…", () => api("api/settings", "PUT", body));
});

refresh().catch((error) => showError(error.message));
