"""Report generation: PDF (reportlab + charts) and CSV — from real DB data."""
from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import DetectionResult, Incident, MlModel, SecurityAlert
from app.services.analytics import analytics_summary

logger = logging.getLogger("aiids.reports")


def _fmt(dt: datetime | None) -> str:
    if dt is None:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _charts_png(summary: dict, out_path: Path) -> Path | None:
    """Render attack + severity bar charts to PNG for embedding in the PDF."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(1, 2, figsize=(10, 3.6))
        attacks = summary.get("by_attack", {})
        if attacks:
            items = sorted(attacks.items(), key=lambda kv: kv[1], reverse=True)[:8]
            axes[0].barh([k for k, _ in items][::-1], [v for _, v in items][::-1], color="#e74c3c")
            axes[0].set_title("Attacks by category")
        else:
            axes[0].text(0.5, 0.5, "No attack data", ha="center")
            axes[0].set_title("Attacks by category")
        sev = summary.get("by_severity", {})
        if sev:
            colors = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#f1c40f",
                      "Low": "#3498db", "Informational": "#95a5a6"}
            keys = list(sev.keys())
            axes[1].bar(keys, [sev[k] for k in keys],
                        color=[colors.get(k, "#7f8c8d") for k in keys])
            axes[1].set_title("Detections by severity")
            axes[1].tick_params(axis="x", rotation=30)
        else:
            axes[1].text(0.5, 0.5, "No detection data", ha="center")
            axes[1].set_title("Detections by severity")
        fig.tight_layout()
        fig.savefig(out_path, dpi=110)
        plt.close(fig)
        return out_path
    except Exception as exc:
        logger.warning("chart render failed: %s", exc)
        return None


def generate_csv_report(db: Session, *, date_from: datetime | None, date_to: datetime | None,
                        report_type: str) -> tuple[str, str, int]:
    """Returns (filename, csv_text, rows)."""
    q = select(SecurityAlert).order_by(SecurityAlert.created_at.desc())
    if date_from:
        q = q.where(SecurityAlert.created_at >= date_from)
    if date_to:
        q = q.where(SecurityAlert.created_at <= date_to)
    if report_type == "investigation":
        q = q.where(SecurityAlert.status.in_(["Investigating", "Resolved", "False Positive"]))
    rows = db.execute(q.limit(50_000)).scalars().all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "alert_id", "created_at", "severity", "status", "attack_type", "source_ip",
        "destination_ip", "destination_port", "protocol", "confidence", "dedup_count",
        "model_version", "incident_id",
    ])
    for a in rows:
        w.writerow([
            a.alert_id, _fmt(a.created_at), a.severity, a.status, a.attack_type,
            a.source_ip, a.destination_ip, a.destination_port, a.protocol,
            f"{a.confidence:.4f}", a.dedup_count, a.model_version, a.incident_id or "",
        ])
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"aiids_{report_type}_{ts}.csv", buf.getvalue(), len(rows)


def generate_pdf_report(db: Session, *, date_from: datetime | None, date_to: datetime | None,
                        report_type: str, title: str = "",
                        incident_id: str | None = None) -> tuple[str, Path, int]:
    """Build a PDF report; returns (filename, path, alert_rows)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    summary = analytics_summary(db, date_from, date_to)
    generated_at = datetime.now(timezone.utc)

    q = select(SecurityAlert).order_by(SecurityAlert.created_at.desc())
    if date_from:
        q = q.where(SecurityAlert.created_at >= date_from)
    if date_to:
        q = q.where(SecurityAlert.created_at <= date_to)
    if report_type == "investigation":
        q = q.where(SecurityAlert.status.in_(["Investigating", "Resolved", "False Positive"]))
    if incident_id:
        q = q.where(SecurityAlert.incident_id == incident_id)
    alerts = db.execute(q.limit(500)).scalars().all()

    settings = get_settings()
    ts = generated_at.strftime("%Y%m%d_%H%M%S")
    kind = title or {"daily": "Daily Security Summary", "weekly": "Weekly Security Summary",
                     "investigation": "Attack Investigation Report",
                     "custom": "Custom Security Report"}.get(report_type, "Security Report")
    filename = f"aiids_{report_type}_{ts}.pdf"
    path = settings.reports_dir / filename

    doc = SimpleDocTemplate(str(path), pagesize=A4, topMargin=1.2 * cm, bottomMargin=1.2 * cm)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph(f"AI-IDS — {kind}", styles["Title"]))
    story.append(Paragraph(f"Generated: {_fmt(generated_at)}", styles["Normal"]))
    if date_from or date_to:
        story.append(Paragraph(
            f"Period: {_fmt(date_from)} → {_fmt(date_to)}", styles["Normal"]))
    story.append(Spacer(1, 0.4 * cm))

    # KPI table
    kpi = [
        ["Total flows analyzed", summary["total_traffic"]],
        ["Normal", summary["normal"]],
        ["Malicious", summary["malicious"]],
        ["False positives (alert status)", summary["false_positives"]],
        ["Alert rows in scope", len(alerts)],
    ]
    t = Table(kpi, hAlign="LEFT", colWidths=[8 * cm, 5 * cm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b0b8c4")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f7")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Attack distribution", styles["Heading2"]))
    if summary["by_attack"]:
        data = [["Category", "Count"]] + [[k, str(v)] for k, v in
                                          sorted(summary["by_attack"].items(), key=lambda kv: -kv[1])]
        story.append(Table(data, hAlign="LEFT", colWidths=[8 * cm, 3 * cm]))
    else:
        story.append(Paragraph("No malicious detections recorded in this period.",
                               styles["Normal"]))
    story.append(Spacer(1, 0.4 * cm))

    # chart — defer file cleanup until after doc.build (reportlab reads lazily)
    settings = get_settings()
    chart_path = settings.reports_dir / f"_chart_{ts}.png"
    embedded_chart = bool(_charts_png(summary, chart_path)) and chart_path.exists()
    if embedded_chart:
        story.append(Image(str(chart_path), width=16 * cm, height=5.8 * cm))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("Top source IPs", styles["Heading2"]))
    if summary["top_sources"]:
        data = [["Source IP", "Alerts"]] + [[s["ip"], str(s["count"])]
                                            for s in summary["top_sources"]]
        story.append(Table(data, hAlign="LEFT", colWidths=[8 * cm, 3 * cm]))
    else:
        story.append(Paragraph("—", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Alerts (most recent up to 60)", styles["Heading2"]))
    header = ["Time", "Severity", "Type", "Source", "Destination", "Status", "Conf"]
    rows = [header]
    for a in alerts[:60]:
        rows.append([
            _fmt(a.created_at), a.severity, a.attack_type[:24],
            f"{a.source_ip}:{a.destination_port}", a.destination_ip[:24],
            a.status, f"{a.confidence:.2f}",
        ])
    if len(rows) == 1:
        rows.append(["-", "-", "No alerts in period", "-", "-", "-", "-"])
    tbl = Table(rows, repeatRows=1, hAlign="LEFT",
                colWidths=[3.1 * cm, 1.8 * cm, 3.4 * cm, 3.3 * cm, 3.0 * cm, 2.6 * cm, 1.2 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2a40")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c8cfda")),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6fa")]),
        ("PADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.5 * cm))

    # model metrics section (actual trained metrics)
    models = db.execute(
        select(MlModel).order_by(MlModel.created_at.desc()).limit(6)
    ).scalars().all()
    story.append(Paragraph("ML model performance (measured at training)", styles["Heading2"]))
    mrows = [["Model", "Version", "Task", "Accuracy", "F1", "FPR"]]
    for m in models:
        met = m.metrics or {}
        acc = met.get("accuracy")
        f1 = met.get("f1", met.get("f1_macro"))
        fpr = met.get("fpr")
        mrows.append([
            f"{m.algorithm}", m.version, m.task,
            f"{acc:.4f}" if isinstance(acc, (int, float)) else "-",
            f"{f1:.4f}" if isinstance(f1, (int, float)) else "-",
            f"{fpr:.4f}" if isinstance(fpr, (int, float)) else "-",
        ])
    if len(mrows) == 1:
        mrows.append(["-", "-", "-", "-", "-", "-"])
    story.append(Table(mrows, hAlign="LEFT",
                       colWidths=[3.6 * cm, 3.4 * cm, 2.4 * cm, 2.2 * cm, 2.2 * cm, 2.2 * cm]))
    story.append(Spacer(1, 0.6 * cm))
    story.append(Paragraph(
        "Confidence values are model scores, not calibrated probabilities. "
        "This report was generated from live application database records.",
        styles["Italic"],
    ))

    doc.build(story)
    if embedded_chart:
        chart_path.unlink(missing_ok=True)
    return filename, path, len(alerts)
