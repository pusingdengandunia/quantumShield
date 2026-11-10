"use strict";

// All scanned data is untrusted (certificate subjects, SSH banners), so the page
// builds DOM nodes with text content and never assigns innerHTML.
const STATUS_ICON = { high: "!!", vulnerable: "!", partial: "◐", protected: "✓", unknown: "?" };
const STATUS_ORDER = ["high", "vulnerable", "partial", "protected", "unknown"];
const ROLE_LABEL = { leaf: "Leaf", intermediate: "Intermediate", root: "Root" };

const TIPS = {
  nama: "Nama aset untuk dashboard dan laporan. Tidak dipakai untuk koneksi. Harus unik.",
  jenis: "Server mendeteksi layanan di port umum secara otomatis. TLS/HTTPS untuk layanan web, SSH untuk server admin, Repo untuk folder kode.",
  host: "Nama host atau IPv4 milik satuanmu, contoh portal.satuan.example. URL yang ditempel otomatis dipecah. Hanya huruf, angka, titik, dan tanda hubung.",
  port: "1 sampai 65535. Umumnya HTTPS 443, SSH 22.",
  path: "Folder di dalam container di bawah /scan, contoh /scan/proyek. Mount folder di docker-compose.yml dulu. URL dan path Windows ditolak.",
  sensitivitas: "Seberapa lama dan seberapa penting data harus rahasia. Ikut menentukan skor risiko dan nilai X.",
  eksposur: "Seberapa mudah trafik disadap: internet paling mudah, LAN tertutup paling sulit.",
  migrasi: "Cara aset dimigrasi. Gateway hanya untuk HTTPS. Legacy untuk perangkat yang tidak bisa diperbarui.",
  izin: "Centang hanya untuk sistem milikmu atau yang izinnya kamu pegang. Target publik tercatat di log pemiliknya. Memindai tanpa izin bisa melanggar hukum, termasuk UU ITE. Sistem TNI AD butuh izin tertulis.",
  bobot: "Porsi dasar, sensitivitas, eksposur, dan migrasi dalam skor konteks. Jumlah keempatnya harus 1.",
  tahun: "Perkiraan tahun komputer kuantum mampu memecah RSA/ECC. Prediksi ini masih diperdebatkan.",
  x: "Berapa tahun data harus tetap rahasia. Mengubah label Mosca, bukan angka risiko.",
  y: "Berapa tahun migrasi aset. Mengubah label Mosca, bukan angka risiko.",
  sumber: "Asal nilai X dan Y. Tampil di detail aset dan PDF.",
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
  if (message) $("notice").hidden = true;
}

function showNotice(message) {
  $("notice").textContent = message || "";
  $("notice").hidden = !message;
}

async function api(path, method = "GET", body) {
  const response = await fetch(path, {
    method,
    headers: { "X-QShield": "1", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const detail = Array.isArray(payload.detail)
      ? payload.detail.map((d) => d.msg.replace(/^Value error, /, "")).join("; ")
      : payload.detail;
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
  showNotice("");
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

/** Run a scan while the header shows which asset is being checked. */
async function runScan() {
  const box = $("progress");
  const fill = $("progress-fill");
  const text = $("progress-text");
  const track = $("progress-track");
  let active = true;
  box.hidden = false;
  fill.style.width = "0";
  track.setAttribute("aria-valuenow", "0");
  text.textContent = "Memulai scan…";
  const poll = async () => {
    while (active) {
      try {
        const progress = await api("api/scans/progress");
        if (active && progress.running) {
          const percent = progress.total ? Math.round((progress.done / progress.total) * 100) : 0;
          fill.style.width = `${percent}%`;
          track.setAttribute("aria-valuenow", String(percent));
          text.textContent = `Memindai ${Math.min(progress.done + 1, progress.total)} dari ${progress.total}: ${progress.current || ""}`;
        }
      } catch { /* The scan request reports its own failure. */ }
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
  };
  poll();
  try {
    await api("api/scans", "POST");
  } finally {
    active = false;
    box.hidden = true;
  }
}

function statusBadge(status, label) {
  return h("span", { class: `status status-${status}` },
    h("span", { class: "status-icon", "aria-hidden": "true" }, STATUS_ICON[status]), label);
}

function formatTime(iso) {
  return new Date(iso).toLocaleString("id-ID", { dateStyle: "medium", timeStyle: "short" });
}

function commonName(subject) {
  const match = /(?:^|,)CN=([^,]+)/.exec(subject || "");
  return match ? match[1] : subject || "–";
}

/* ---------- Tabs ---------- */

const TABS = ["ringkasan", "aset", "kelola"];

function selectTab(name, focus = false) {
  const chosen = TABS.includes(name) && !$(`tab-${name}`).hidden ? name : "ringkasan";
  for (const tab of TABS) {
    const selected = tab === chosen;
    const button = $(`tab-${tab}`);
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
    $(`panel-${tab}`).hidden = !selected;
  }
  if (focus) $(`tab-${chosen}`).focus();
  if (location.hash !== `#${chosen}`) history.replaceState(null, "", `#${chosen}`);
}

for (const tab of TABS) {
  $(`tab-${tab}`).addEventListener("click", () => selectTab(tab));
  $(`tab-${tab}`).addEventListener("keydown", (event) => {
    if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
    const visible = TABS.filter((name) => !$(`tab-${name}`).hidden);
    const step = event.key === "ArrowRight" ? 1 : -1;
    selectTab(visible.at((visible.indexOf(tab) + step) % visible.length), true);
  });
}

/* ---------- Summary ---------- */

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

function renderStatusBar(data) {
  const present = STATUS_ORDER.filter((status) => data.status_counts[status]);
  const words = present.map((status) => `${data.status_counts[status]} ${data.status_labels[status]}`);
  const bar = $("status-bar");
  bar.setAttribute("aria-label", `Distribusi status: ${words.join(", ")}`);
  bar.replaceChildren(...present.map((status) => {
    const part = h("span", { class: `seg-${status}`, title: `${data.status_labels[status]}: ${data.status_counts[status]}` });
    part.style.flex = String(data.status_counts[status]);
    return part;
  }));
  $("status-legend").replaceChildren(...present.map((status) => h("li", {},
    statusBadge(status, `${data.status_labels[status]} ${data.status_counts[status]}`))));
}

function svg(tag, attributes = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
  node.append(...children);
  return node;
}

function renderTrend(history) {
  const points = history.filter((scan) => scan.readiness != null);
  const host = $("trend");
  host.replaceChildren();
  if (points.length < 2) {
    host.append(h("p", { class: "muted" }, "Tren muncul setelah dua scan."));
    return;
  }

  const W = 560, H = 210, left = 34, right = 12, top = 12, bottom = 12;
  const x = (i) => left + (i / (points.length - 1)) * (W - left - right);
  const y = (value) => top + (1 - value / 100) * (H - top - bottom);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", tabindex: 0,
    "aria-label": `Tren skor dari ${points[0].readiness} ke ${points.at(-1).readiness}. Tekan panah kiri atau kanan untuk membaca tiap scan.` });
  for (const tick of [0, 50, 100]) {
    root.append(svg("line", { x1: left, x2: W - right, y1: y(tick), y2: y(tick), stroke: "var(--grid)" }));
    const label = svg("text", { x: left - 8, y: y(tick) + 4, "text-anchor": "end", "font-size": 12, fill: "var(--text-secondary)" });
    label.textContent = tick;
    root.append(label);
  }
  const path = points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(p.readiness).toFixed(1)}`).join("");
  root.append(svg("path", { d: path, fill: "none", stroke: "var(--series-1)", "stroke-width": 2, "stroke-linejoin": "round" }));
  const marker = svg("circle", { r: 5, fill: "var(--series-1)", stroke: "var(--surface-1)", "stroke-width": 2,
    cx: x(points.length - 1), cy: y(points.at(-1).readiness) });
  root.append(marker);

  const tooltip = h("div", { class: "tooltip", hidden: true });
  const spoken = h("p", { class: "sr-only", "aria-live": "polite" });
  const last = points.length - 1;
  let current = last;
  const show = (index, announce) => {
    current = index;
    const box = root.getBoundingClientRect();
    const scale = W / box.width;
    const point = points.at(index);
    const label = `${point.readiness.toFixed(1)} · ${formatTime(point.finished_at)}`;
    marker.setAttribute("cx", x(index));
    marker.setAttribute("cy", y(point.readiness));
    tooltip.hidden = false;
    tooltip.textContent = label;
    tooltip.style.left = `${Math.min(box.width - 90, Math.max(90, x(index) / scale))}px`;
    tooltip.style.top = `${Math.max(26, y(point.readiness) / scale - 10)}px`;
    if (announce) spoken.textContent = `Scan ${index + 1} dari ${points.length}: skor ${label}`;
  };
  const reset = () => {
    current = last;
    tooltip.hidden = true;
    marker.setAttribute("cx", x(last));
    marker.setAttribute("cy", y(points.at(-1).readiness));
  };
  root.addEventListener("pointermove", (event) => {
    const box = root.getBoundingClientRect();
    const ratio = ((event.clientX - box.left) * (W / box.width) - left) / (W - left - right);
    show(Math.max(0, Math.min(last, Math.round(ratio * last))), false);
  });
  root.addEventListener("pointerleave", () => { if (document.activeElement !== root) reset(); });
  root.addEventListener("focus", () => show(current, true));
  root.addEventListener("blur", reset);
  root.addEventListener("keydown", (event) => {
    const next = { ArrowLeft: current - 1, ArrowRight: current + 1, Home: 0, End: last }[event.key];
    if (next == null) return;
    event.preventDefault();
    show(Math.max(0, Math.min(last, next)), true);
  });
  host.append(root, tooltip, spoken);
}

function renderKpis(data) {
  const kpi = data.kpi;
  const tile = (label, value, note, alert) => h("div", { class: `kpi${alert ? " alert" : ""}` },
    h("div", { class: "label" }, label), h("div", { class: "value" }, String(value)), h("div", { class: "note" }, note));
  $("kpis").replaceChildren(
    tile("Prioritas P1", kpi.p1, "Berisiko tinggi, tangani segera", kpi.p1 > 0),
    tile("Rentan Mosca", kpi.mosca_vulnerable, "Data rahasia melewati Q-Day"),
    tile("Autentikasi PQC", kpi.pqc_auth, `Dari ${kpi.reachable} aset terpindai`),
    tile("Terlindungi penuh", kpi.protected, `${data.status_counts.partial} lagi terlindungi sebagian`),
  );
}

function renderTopLists(data) {
  const risky = data.rows.filter((row) => row.assessment.risk > 0).slice(0, 3);
  $("top-risks").replaceChildren(...(risky.length ? risky.map((row) => h("li", {},
    h("span", { class: "main" }, h("span", { class: "name" }, row.target_name), " ", h("span", { class: `priority ${row.priority}` }, row.priority),
      h("span", { class: "sub", style: null }, h("br"), row.assessment.drivers?.[0]?.label || row.status_label)),
    h("span", { class: "number" }, row.assessment.risk.toFixed(1)))) : [h("li", { class: "sub" }, "Tidak ada aset berisiko.")]));
  const actions = data.roadmap.slice(0, 3);
  $("next-actions").replaceChildren(...(actions.length ? actions.map((entry) => h("li", {},
    h("span", { class: "main" }, h("span", { class: "name" }, entry.target), h("span", { class: "sub" }, h("br"), entry.action)))) : [h("li", { class: "sub" }, "Tidak ada tindakan tertunda.")]));
}

/* ---------- Assets ---------- */

function authLabel(row) {
  const audit = row.detail.pki;
  if (audit) {
    const text = { pqc: "PQC", mixed: "Campuran", classic: "Klasik" }[audit.auth_status];
    const sub = audit.auth_status === "pqc" ? audit.chain[0].key_algorithm : audit.weakest_link;
    const trust = audit.trust.verified === false ? " · tidak tepercaya" : "";
    return [text, `${sub || ""}${trust}`];
  }
  if (row.target.kind === "ssh" && row.reachable) return ["Klasik", "Host key SSH"];
  return ["–", ""];
}

function kexLabel(row) {
  const kex = row.items.find((item) => item.role === "kex");
  if (kex) return [kex.quantum === "safe" ? "Hybrid" : "Klasik", kex.algorithm];
  if (row.target.kind === "repo") return ["Kode", `${row.items.length} temuan`];
  return ["–", ""];
}

function scoreBlock(row) {
  const a = row.assessment;
  const entry = (term, value) => [h("dt", {}, term), h("dd", {}, value)];
  const drivers = a.drivers || [];
  return h("div", { class: "detail-block" },
    h("h3", {}, `Mengapa skornya ${a.risk.toFixed(1)}`),
    a.context != null ? h("div", { class: "formula" }, `100 × A ${a.A.toFixed(1)} × konteks ${a.context.toFixed(2)}`) : null,
    drivers.length
      ? h("ul", {}, drivers.map((driver) => h("li", {}, `${driver.label} (A ${driver.A.toFixed(1)})`)))
      : h("p", { class: "detail-note" }, "Tidak ada pendorong risiko."),
    h("dl", { class: "factors" },
      entry("Sensitivitas S", a.S.toFixed(1)),
      entry("Eksposur E", a.E.toFixed(1)),
      entry("Migrasi M", a.M.toFixed(1)),
      entry("Mosca", a.mosca_vulnerable ? `X + Y > Z (${a.X} + ${a.Y} > ${a.Z}): rentan HNDL`
        : a.X + a.Y > a.Z ? "Kerahasiaan sudah aman dari HNDL"
          : `X + Y ≤ Z (${a.X} + ${a.Y} ≤ ${a.Z}): belum mendesak`),
      entry("Sumber X, Y", state.settings.mosca_source || "Asumsi awal, belum ada sumber resmi")));
}

function chainBlock(row) {
  const audit = row.detail.pki;
  if (!audit) {
    const items = row.items.filter((item) => item.role !== "code");
    const codeHits = row.items.length - items.length;
    return h("div", { class: "detail-block" }, h("h3", {}, "Kriptografi terdeteksi"),
      items.length ? h("ul", {}, items.map((item) => h("li", {}, `${item.algorithm} (${item.role})`))) : null,
      codeHits ? h("p", { class: "detail-note" }, `${codeHits} pemakaian di ${row.detail.files_scanned} berkas.`) : null,
      !items.length && !codeHits ? h("p", { class: "detail-note" }, "Tidak ada.") : null);
  }
  const trust = audit.trust;
  const trustText = trust.verified === true ? "Rantai tepercaya" : trust.verified === false ? `Tidak tepercaya: ${trust.code || "-"}` : "Kepercayaan tidak diperiksa";
  return h("div", { class: "detail-block" },
    h("h3", {}, "Rantai PKI"),
    h("ol", { class: "chain" }, audit.chain.map((entry) => {
      const size = entry.key_size && ["RSA", "DSA"].includes(entry.key_algorithm) ? `-${entry.key_size}` : "";
      return h("li", {},
        h("div", { class: "role" }, ROLE_LABEL[entry.role]),
        h("div", { class: "cn" }, commonName(entry.subject)),
        h("div", { class: "meta" }, entry.pqc ? h("span", { class: "pq-tag" }, "PQC ") : null,
          `${entry.key_algorithm}${size} · ditandatangani ${entry.signature_algorithm}`),
        h("div", { class: "meta" }, entry.days_left < 0 ? "Sudah kedaluwarsa" : `Berlaku ${entry.days_left} hari lagi`));
    })),
    h("p", { class: "detail-note" }, `${trustText}. Nama host ${trust.hostname_match ? "cocok" : "tidak cocok"}.`),
    audit.negotiated_signature ? h("p", { class: "detail-note" }, `Tanda tangan handshake: ${audit.negotiated_signature}.`) : null,
    audit.root_in_chain ? null : h("p", { class: "detail-note" }, "Root tidak dikirim server, jadi algoritmanya tidak diperiksa."),
    row.detail.versions ? h("p", { class: "detail-note" }, `Protokol aktif: ${row.detail.versions.join(", ")}.`) : null);
}

function benchmarkTable(bench) {
  const line = (name, data) => h("tr", {}, h("td", {}, name), h("td", {}, data.median_ms.toFixed(1)), h("td", {}, data.bytes.toLocaleString("id-ID")));
  return h("div", { class: "detail-block" },
    h("h3", {}, `Benchmark gateway (median ${bench.classic.samples} handshake)`),
    h("table", { class: "mini" },
      h("thead", {}, h("tr", {}, h("th", {}, "Grup"), h("th", {}, "Waktu (ms)"), h("th", {}, "Data (byte)"))),
      h("tbody", {}, line(bench.classic_group, bench.classic), line(bench.hybrid_group, bench.hybrid))),
    h("p", { class: "detail-note" }, `Overhead hybrid: ${bench.extra_ms >= 0 ? "+" : ""}${bench.extra_ms.toFixed(1)} ms, +${bench.extra_bytes.toLocaleString("id-ID")} byte. Waktu mencakup start proses openssl; selisih kecil tertutup noise.`));
}

function detailRow(row, readOnly) {
  const target = row.target;
  const actions = h("div", { class: "detail-actions" });
  if (!readOnly && target.kind === "tls" && target.migration === "gateway" && !row.detail.hybrid) {
    actions.append(h("button", { class: "button primary", type: "button", onclick: (event) => act(event.target, "Memasang…", async () => {
      await api(`api/targets/${target.id}/gateway`, "POST");
      await runScan();
    }) }, "Terapkan PQC Gateway"));
  }
  if (!readOnly && target.gateway_port) {
    actions.append(h("button", { class: "button", type: "button", onclick: (event) => act(event.target, "Mengukur…", () => api(`api/targets/${target.id}/benchmark`, "POST")) }, "Jalankan benchmark"));
    actions.append(h("button", { class: "button", type: "button", onclick: (event) => act(event.target, "Melepas…", async () => {
      await api(`api/targets/${target.id}/gateway`, "DELETE");
      await runScan();
    }) }, "Lepas gateway"));
  }
  const gatewayNote = target.gateway_port
    ? h("p", { class: "detail-note" }, `Gateway ${target.gateway_status || "-"} di port ${target.gateway_port}.${readOnly ? "" : ` Dari komputer ini: https://localhost:${target.gateway_port}`}`)
    : null;
  const findings = row.findings.length
    ? h("ul", {}, row.findings.map((finding) => h("li", { class: `finding-${finding.severity}` }, finding.text)))
    : h("p", { class: "detail-note" }, "Tidak ada temuan.");
  return h("tr", { class: "detail", id: `detail-${row.target_id}` }, h("td", { colspan: 6 },
    h("div", { class: "detail-grid" },
      scoreBlock(row),
      h("div", { class: "detail-block" }, h("h3", {}, "Temuan"), findings),
      chainBlock(row),
      row.benchmark ? benchmarkTable(row.benchmark) : null),
    gatewayNote, actions.children.length ? actions : null));
}

function assetRow(row, readOnly) {
  const [kexMain, kexSub] = kexLabel(row);
  const [authMain, authSub] = authLabel(row);
  const fill = h("div", { class: "risk-fill" });
  fill.style.width = `${row.assessment.risk}%`;
  const open = openRow === row.target_id;
  // The name button is the keyboard and screen-reader control. A click anywhere
  // on the row, including the button itself, bubbles up to this one handler.
  const toggle = (event) => {
    if (event.target.closest("a, .detail")) return;
    const refocus = document.activeElement?.classList.contains("row-toggle");
    openRow = open ? null : row.target_id;
    renderAssets(state);
    if (refocus) {
      for (const button of document.querySelectorAll(".row-toggle")) {
        if (button.dataset.row === String(row.target_id)) button.focus();
      }
    }
  };
  const nameButton = h("button", { class: "row-toggle name", type: "button", "aria-expanded": String(open),
    "aria-controls": open ? `detail-${row.target_id}` : null }, row.target_name);
  nameButton.dataset.row = row.target_id;
  const cells = h("tr", { class: `asset${open ? " open" : ""}`, onclick: toggle },
    h("td", { class: "cell-prio", "data-label": "Prioritas" }, h("span", { class: `priority ${row.priority}` }, row.priority)),
    h("td", { class: "cell-name" }, nameButton),
    h("td", { "data-label": "Key exchange" }, kexMain, h("span", { class: "sub" }, kexSub)),
    h("td", { "data-label": "Autentikasi (PKI)" }, authMain, h("span", { class: "sub" }, authSub)),
    h("td", { class: "cell-risk", "data-label": "Risiko" }, h("div", { class: "risk" }, h("div", { class: "risk-track" }, fill), h("span", { class: "risk-number" }, row.assessment.risk.toFixed(1)))),
    h("td", { class: "cell-status", "data-label": "Status" }, statusBadge(row.status, row.status_label)));
  return openRow === row.target_id ? [cells, detailRow(row, readOnly)] : [cells];
}

function renderAssets(data) {
  const body = $("assets").tBodies[0];
  body.replaceChildren();
  if (!data.rows.length) {
    body.append(h("tr", {}, h("td", { colspan: 6, class: "muted" }, "Belum ada hasil. Daftarkan target lalu jalankan scan.")));
    return;
  }
  const byId = new Map(data.rows.map((row) => [row.target_id, row]));
  for (const server of data.servers) {
    if (server.services > 1) {
      body.append(h("tr", { class: "server-row" }, h("td", { colspan: 6 },
        h("strong", {}, server.server), ` · ${server.services} layanan · risiko tertinggi ${server.risk.toFixed(1)} · ${server.priority}`)));
    }
    for (const id of server.target_ids) body.append(...assetRow(byId.get(id), data.read_only));
  }
}

function renderRoadmap(entries) {
  const body = $("roadmap").tBodies[0];
  body.replaceChildren();
  if (!entries.length) {
    body.append(h("tr", {}, h("td", { colspan: 3, class: "muted" }, "Tidak ada aset yang perlu dimigrasi.")));
  }
  for (const entry of entries) {
    body.append(h("tr", {}, h("td", { "data-label": "Fase" }, entry.phase), h("td", { "data-label": "Aset" }, entry.target), h("td", { "data-label": "Tindakan" }, entry.action)));
  }
}

/* ---------- Manage ---------- */

function fillSelect(name, options) {
  const select = $("target-form").elements[name];
  if (select.options.length) return;
  for (const [value, label] of Object.entries(options)) select.append(h("option", { value }, label));
}

function renderManage(data) {
  $("tab-kelola").hidden = data.read_only;
  $("scan-button").hidden = data.read_only;
  $("readonly-banner").hidden = !data.read_only;
  if (data.read_only) return;
  fillSelect("sensitivity", data.options.sensitivity);
  fillSelect("exposure", data.options.exposure);
  fillSelect("migration", data.options.migration);
  const list = data.targets.map((target) => h("li", {},
    h("span", {}, target.name, h("span", { class: "where" }, target.kind === "repo" ? target.path : `${target.host}:${target.port}`)),
    h("button", { class: "button", type: "button", "aria-label": `Hapus ${target.name}`,
      onclick: (event) => act(event.target, "…", () => api(`api/targets/${target.id}`, "DELETE")) }, "Hapus")));
  $("targets").replaceChildren(...(list.length ? list : [h("li", { class: "muted" }, "Belum ada target.")]));
  const form = $("settings-form");
  if (document.activeElement?.form !== form) {
    for (const [key, value] of Object.entries(data.settings)) {
      if (form.elements[key]) form.elements[key].value = value;
    }
  }
}

function syncTargetForm() {
  const form = $("target-form");
  const kind = form.elements.kind.value;
  const visible = {
    named: kind !== "server",
    host: kind !== "repo",
    port: kind === "tls" || kind === "ssh",
    repo: kind === "repo",
  };
  for (const field of form.querySelectorAll("[data-for]")) field.hidden = !visible[field.dataset.for];
  if (kind === "ssh") form.elements.port.value = 22;
  if (kind === "tls") form.elements.port.value = 443;
  $("target-submit").textContent = kind === "server" ? "Deteksi layanan" : "Tambah ke allowlist";
  $("discovered").hidden = true;
}

$("target-form").elements.kind.addEventListener("change", syncTargetForm);

function targetChoices(form) {
  return { sensitivity: form.elements.sensitivity.value, exposure: form.elements.exposure.value, migration: form.elements.migration.value };
}

function renderDiscovered(result, form) {
  const box = $("discovered");
  box.hidden = false;
  if (!result.services.length) {
    box.replaceChildren(h("p", { class: "muted" }, `Tidak ada layanan TLS atau SSH di ${result.host}. Port yang dicek: ${result.checked.join(", ")}.`));
    return;
  }
  const boxes = result.services.map((service) => {
    const input = h("input", { type: "checkbox", checked: !service.registered, disabled: service.registered });
    input.dataset.port = service.port;
    input.dataset.kind = service.kind;
    return h("label", {}, input, `${service.port} · ${service.label}${service.registered ? " (sudah terdaftar)" : ""}`);
  });
  const add = h("button", { class: "button primary", type: "button", onclick: (event) => act(event.target, "Menambahkan…", async () => {
    const services = boxes.map((label) => label.querySelector("input")).filter((input) => input.checked && !input.disabled)
      .map((input) => ({ port: Number(input.dataset.port), kind: input.dataset.kind }));
    if (!services.length) throw new Error("Pilih minimal satu layanan.");
    await api("api/servers", "POST", { host: result.host, services, ...targetChoices(form), authorized: form.elements.authorized.checked });
    await runScan();
    box.hidden = true;
    form.reset();
    syncTargetForm();
    selectTab("aset");
  }) }, "Tambahkan dan pindai");
  box.replaceChildren(h("h3", {}, `Layanan di ${result.host}`), ...boxes, add);
}

$("target-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.target;
  const kind = form.elements.kind.value;
  const authorized = form.elements.authorized.checked;
  const button = $("target-submit");
  if (kind === "server") {
    act(button, "Mendeteksi…", async () => {
      const result = await api("api/servers/discover", "POST", { host: form.elements.host.value, authorized });
      renderDiscovered(result, form);
    });
    return;
  }
  const body = { name: form.elements.name.value, kind, ...targetChoices(form), authorized,
    host: kind === "repo" ? null : form.elements.host.value,
    port: kind === "repo" ? null : Number(form.elements.port.value),
    path: kind === "repo" ? form.elements.path.value : null };
  act(button, "Menyimpan…", async () => {
    await api("api/targets", "POST", body);
    form.reset();
    syncTargetForm();
    showNotice(`${body.name} masuk allowlist. Jalankan scan untuk melihat hasilnya.`);
  });
});

$("settings-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.target;
  const body = Object.fromEntries([...new FormData(form)].map(([key, value]) => [key, key === "mosca_source" ? value : Number(value)]));
  act(form.querySelector("button"), "Menyimpan…", async () => {
    await api("api/settings", "PUT", body);
    showNotice("Pengaturan tersimpan. Berlaku pada scan berikutnya.");
  });
});

$("scan-button").addEventListener("click", (event) => act(event.target, "Memindai…", runScan));

/* ---------- Info tooltips ---------- */

const tip = h("div", { class: "tip", role: "tooltip", id: "tip", hidden: true });
document.body.append(tip);
let tipOwner = null;

function closeTip() {
  if (!tipOwner) return;
  tipOwner.setAttribute("aria-expanded", "false");
  tipOwner.removeAttribute("aria-describedby");
  tipOwner = null;
  tip.hidden = true;
}

function openTip(button, text) {
  closeTip();
  tipOwner = button;
  tip.textContent = text;
  tip.hidden = false;
  button.setAttribute("aria-expanded", "true");
  button.setAttribute("aria-describedby", "tip");
  const anchor = button.getBoundingClientRect();
  const box = tip.getBoundingClientRect();
  const left = Math.max(12, Math.min(anchor.left, innerWidth - box.width - 12));
  const below = anchor.bottom + 8;
  tip.style.left = `${left}px`;
  tip.style.top = `${below + box.height > innerHeight ? Math.max(12, anchor.top - box.height - 8) : below}px`;
}

function makeInfoButton(key, name) {
  const text = TIPS[key];
  const button = h("button", { class: "info", type: "button", "aria-label": `Info: ${name}`, "aria-expanded": "false",
    onclick: (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (tipOwner === button) closeTip();
      else openTip(button, text);
    },
    onfocus: () => { if (button.matches(":focus-visible") && tipOwner !== button) openTip(button, text); },
    onblur: closeTip }, "i");
  return button;
}

for (const field of document.querySelectorAll("[data-tip]")) {
  const head = field.querySelector(".field-head");
  head.append(makeInfoButton(field.dataset.tip, head.querySelector("label").textContent.trim()));
}
for (const holder of document.querySelectorAll("[data-tip-inline]")) {
  const title = holder.parentElement.querySelector(".field-title").textContent.trim();
  holder.replaceWith(makeInfoButton(holder.dataset.tipInline, title));
}
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && tipOwner) {
    const owner = tipOwner;
    closeTip();
    owner.focus();
  }
});
document.addEventListener("click", closeTip);
window.addEventListener("scroll", closeTip, { passive: true });
window.addEventListener("resize", closeTip);

/* ---------- Page data ---------- */

async function refresh() {
  state = await api("api/dashboard");
  $("loading").hidden = true;
  const hasResults = state.rows.length > 0;
  $("empty-state").hidden = hasResults;
  $("summary-content").hidden = !hasResults;
  renderScore(state);
  renderStatusBar(state);
  renderTrend(state.history);
  renderKpis(state);
  renderTopLists(state);
  renderAssets(state);
  renderRoadmap(state.roadmap);
  renderManage(state);
  selectTab(location.hash.slice(1) || "ringkasan");
}

syncTargetForm();
selectTab(location.hash.slice(1) || "ringkasan");
window.addEventListener("hashchange", () => selectTab(location.hash.slice(1)));
refresh().catch((error) => {
  $("loading").textContent = "Data dashboard gagal dimuat. Muat ulang halaman, atau periksa apakah layanan Q-Shield berjalan.";
  showError(error.message);
});
