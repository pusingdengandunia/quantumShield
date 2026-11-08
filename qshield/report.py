"""M4: commander-ready PDF report."""
from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _cell(text, style) -> Paragraph:
    # Certificate subjects and banners come from scanned hosts, so they are escaped.
    return Paragraph(escape(str(text)), style)


def _table(rows: list[list], widths: list[float]) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeea")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bbbbb5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def build_pdf(data: dict) -> bytes:
    buffer = io.BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=A4, title="Laporan Kesiapan Kuantum",
                                 author="Kartika Q-Shield", leftMargin=18 * mm, rightMargin=18 * mm)
    styles = getSampleStyleSheet()
    body, heading = styles["BodyText"], styles["Heading2"]
    small = styles["BodyText"].clone("small", fontSize=8.5, leading=11)
    story = [
        Paragraph("Laporan Kesiapan Kuantum", styles["Title"]),
        Paragraph(escape(f"Kartika Q-Shield. Waktu scan: {data['scanned_at'] or '-'} (UTC)."), body),
        Spacer(1, 6 * mm),
        Paragraph("Ringkasan eksekutif", heading),
        Paragraph(escape(f"Skor kesiapan kuantum satuan: {data['readiness'] if data['readiness'] is not None else '-'} dari 100."), body),
        Paragraph(escape(data["summary"]), body),
        Spacer(1, 4 * mm),
        Paragraph("Risiko per aset", heading),
    ]
    rows = [[_cell(title, small) for title in ("Prio", "Aset", "Risiko", "Status", "Key exchange", "Autentikasi")]]
    for row in data["rows"]:
        kex = next((item["algorithm"] for item in row["items"] if item["role"] == "kex"), "-")
        audit = row["detail"].get("pki") or {}
        auth = audit.get("weakest_link") or ("PQC" if audit.get("auth_status") == "pqc" else "-")
        if row["target"]["kind"] == "ssh" and row["reachable"]:
            auth = "Klasik (host key SSH)"
        rows.append([_cell(value, small) for value in (
            row["priority"], row["target_name"], f"{row['assessment']['risk']:.1f}", row["status_label"], kex, auth)])
    story.append(_table(rows, [11 * mm, 44 * mm, 14 * mm, 29 * mm, 33 * mm, 39 * mm]))
    story += [Spacer(1, 4 * mm), Paragraph("Roadmap migrasi", heading)]
    if data["roadmap"]:
        rows = [[_cell(title, small) for title in ("Fase", "Aset", "Tindakan")]]
        rows += [[_cell(entry["phase"], small), _cell(entry["target"], small), _cell(entry["action"], small)]
                 for entry in data["roadmap"]]
        story.append(_table(rows, [30 * mm, 42 * mm, 98 * mm]))
    else:
        story.append(Paragraph("Semua aset terpindai sudah terlindungi.", body))
    settings = data["settings"]
    source = settings["mosca_source"] or "asumsi awal, belum ada sumber resmi"
    story += [
        Spacer(1, 6 * mm),
        Paragraph(escape(f"Asumsi: komputer kuantum relevan tahun {settings['quantum_year']}. "
                         f"Masa rahasia X: rahasia {settings['x_rahasia']}, internal {settings['x_internal']}, "
                         f"publik {settings['x_publik']} tahun. Lama migrasi Y: gateway {settings['y_gateway']}, "
                         f"update {settings['y_update']}, legacy {settings['y_legacy']} tahun. Sumber: {source}. "
                         "Nilai ini bisa diatur karena prediksi timeline masih diperdebatkan. "
                         "Hybrid melindungi kerahasiaan dari HNDL; autentikasi klasik tetap perlu migrasi ke ML-DSA."), small),
    ]
    document.build(story)
    return buffer.getvalue()
