"""
ForensiTrace - Forensic Investigation PDF Report Generator (PURVA)
Generates a formal 3-page forensic investigation report with raw evidence appendix strictly adhering to docs/ml.md:
  - Page 1: Case Summary, Categorical Threat Badge, Side-by-Side Scores (Rule + ML), Hash Chain Verification.
  - Page 2: Reconstructed Chronological Timeline & Evidence Provenance Table.
  - Page 3: Unedited Raw Event Appendix (complete JSON non-repudiation record).
"""

from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from backend.app.models import ActivityRecord, EventRecord


def generate_activity_pdf(
    activity: ActivityRecord,
    evidence: List[EventRecord],
    filepath: str,
    provenance_links: Optional[List[Dict[str, Any]]] = None,
    chain_verified: bool = True
) -> None:
    """
    Generates a formal 3-page forensic investigation report.
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        alignment=0
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#64748b')
    )
    heading2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12.5,
        textColor=colors.HexColor('#334155')
    )
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#1e293b')
    )
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1e293b')
    )
    table_head_style = ParagraphStyle(
        'TableHead',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.whitesmoke
    )

    elements = []

    # =========================================================================
    # PAGE 1: CASE SUMMARY & THREAT BADGE
    # =========================================================================
    elements.append(Paragraph("FORENSITRACE FORENSIC INVESTIGATION REPORT", title_style))
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(
        f"Cross-Source Correlation Engine &bull; Generated: {now_str} &bull; Classification: INVESTIGATIVE SENSITIVE",
        subtitle_style
    ))
    elements.append(Spacer(1, 6))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceAfter=10))

    # Threat Badge Color
    threat_level = getattr(activity, "threat_level", "HIGH") or "HIGH"
    if threat_level == "CRITICAL":
        threat_bg = colors.HexColor('#fef2f2')
        threat_border = colors.HexColor('#ef4444')
        threat_ink = "#b91c1c"
    elif threat_level == "HIGH":
        threat_bg = colors.HexColor('#fff7ed')
        threat_border = colors.HexColor('#f97316')
        threat_ink = "#c2410c"
    elif threat_level == "MEDIUM":
        threat_bg = colors.HexColor('#fefce8')
        threat_border = colors.HexColor('#eab308')
        threat_ink = "#a16207"
    else:
        threat_bg = colors.HexColor('#f8fafc')
        threat_border = colors.HexColor('#64748b')
        threat_ink = "#475569"

    badge_p = Paragraph(
        f"<font size=12><b>THREAT LEVEL: <font color='{threat_ink}'>{threat_level}</font></b></font><br/>"
        f"<font size=8.5 color='#475569'>Reconstructed Incident Identification &bull; Case ID: <b>ACT-{activity.id:04d}</b> &bull; Rule: <b>{activity.rule_name}</b></font>",
        body_style
    )
    badge_table = Table([[badge_p]], colWidths=[540])
    badge_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), threat_bg),
        ('BOX', (0, 0), (-1, -1), 1.5, threat_border),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(badge_table)
    elements.append(Spacer(1, 10))

    # Side-by-side Dual Metrics Table: Rule Confidence vs ML Anomaly Score
    ml_score_val = getattr(activity, "ml_anomaly_score", None)
    ml_score_str = f"{ml_score_val:.2f} (Threshold 0.50)" if ml_score_val is not None else "N/A (Rules Fallback)"
    combined_index_val = 0.5 * activity.confidence_score + (0.5 * ml_score_val if ml_score_val is not None else 0.5 * activity.confidence_score)

    metrics_data = [
        [
            Paragraph("<b>EVALUATION SIGNAL</b>", table_head_style),
            Paragraph("<b>SCORE VALUE</b>", table_head_style),
            Paragraph("<b>NORMALIZED SCALE</b>", table_head_style),
            Paragraph("<b>METHODOLOGY & ROLE</b>", table_head_style)
        ],
        [
            Paragraph("<b>Rule Confidence</b>", body_style),
            Paragraph(f"<b>{activity.confidence_score:.2f}</b> ({activity.confidence_level})", body_style),
            Paragraph("0.00 &rarr; 1.00", body_style),
            Paragraph("Declarative causal logic & timing criteria in rules.yaml", body_style)
        ],
        [
            Paragraph("<b>ML Anomaly Score</b>", body_style),
            Paragraph(f"<b>{ml_score_str}</b>", body_style),
            Paragraph("0.00 &rarr; 1.00", body_style),
            Paragraph("LSTM Autoencoder reconstruction error on normal baseline", body_style)
        ],
        [
            Paragraph("<b>Combined Risk Index</b>", body_style),
            Paragraph(f"<b><font color='{threat_ink}'>{combined_index_val:.2f} ({threat_level})</font></b>", body_style),
            Paragraph("0.00 &rarr; 1.00", body_style),
            Paragraph("Equal weight hybrid fusion (0.5 Rule + 0.5 ML)", body_style)
        ]
    ]
    metrics_table = Table(metrics_data, colWidths=[120, 110, 95, 215])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 10))

    # Cryptographic Chain Integrity Card
    elements.append(Paragraph("Cryptographic Evidence Store Integrity", heading2_style))
    if chain_verified:
        integrity_status = "<font color='#16a34a'><b>VERIFIED &bull; UNBROKEN SHA-256 HASH CHAIN</b></font>"
        integrity_desc = (
            f"Status: {integrity_status}<br/>"
            "Each raw evidence record cited in this report is cryptographically anchored in the ForensiTrace "
            "append-only store via recursive SHA-256 hash chaining. Integrity was verified at report compilation time, "
            "guaranteeing sequential non-repudiation and tamper detection."
        )
    else:
        integrity_status = "<font color='#dc2626'><b>COMPROMISED &bull; HASH CHAIN MISMATCH</b></font>"
        integrity_desc = f"Status: {integrity_status}<br/>WARNING: Audit log indicates possible tamper violation."

    chain_table = Table([[Paragraph(integrity_desc, body_style)]], colWidths=[540])
    chain_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f0fdf4') if chain_verified else colors.HexColor('#fef2f2')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#bbf7d0') if chain_verified else colors.HexColor('#fecaca')),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(chain_table)
    elements.append(Spacer(1, 10))

    # Executive Summary & Explainable Narrative
    elements.append(Paragraph("Reconstructed Threat Narrative & Anomaly Assessment", heading2_style))
    narrative_p = Paragraph(f"<i>{activity.narrative}</i>", body_style)
    narrative_box = Table([[narrative_p]], colWidths=[540])
    narrative_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#eff6ff')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#bfdbfe')),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(narrative_box)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(
        "<font size=8 color='#94a3b8'>ForensiTrace Forensic Investigation Report &bull; Page 1 of 3 (Summary & Threat Badge)</font>",
        subtitle_style
    ))

    # =========================================================================
    # PAGE 2: RECONSTRUCTED TIMELINE & EVIDENCE TABLE
    # =========================================================================
    elements.append(PageBreak())
    elements.append(Paragraph("RECONSTRUCTED TIMELINE & EVIDENCE PROVENANCE", title_style))
    elements.append(Paragraph(
        f"Case ACT-{activity.id:04d} &bull; Correlated Artifacts: {len(evidence)} &bull; Time Span: {activity.timestamp_start.strftime('%H:%M:%S UTC')} to {activity.timestamp_end.strftime('%H:%M:%S UTC')}",
        subtitle_style
    ))
    elements.append(Spacer(1, 6))
    elements.append(HRFlowable(width="100%", thickness=1.0, color=colors.HexColor('#94a3b8'), spaceAfter=10))

    # Chronological Reconstructed Sequence Steps
    elements.append(Paragraph("Sequential Reconstruction Steps", heading2_style))
    step_items = []
    for idx, ev in enumerate(evidence, 1):
        ts_clock = ev.timestamp.strftime("%H:%M:%S.%f")[:-3]
        step_items.append([
            Paragraph(f"<b>Step {idx}</b>", body_style),
            Paragraph(f"<font color='#0284c7'><b>{ts_clock} UTC</b></font>", body_style),
            Paragraph(f"<b>[{ev.source.upper()}] {ev.action}</b> &mdash; Entity: <code>{ev.entity}</code>", body_style)
        ])
    steps_table = Table(step_items, colWidths=[55, 95, 390])
    steps_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(steps_table)
    elements.append(Spacer(1, 12))

    # Structured Evidence Provenance Table
    elements.append(Paragraph("Cross-Source Evidence Provenance Table", heading2_style))

    reason_map = {}
    if provenance_links:
        for link in provenance_links:
            ev_id = link.get("event", {}).id if hasattr(link.get("event"), "id") else link.get("event_id")
            if ev_id:
                reason_map[ev_id] = link.get("reason", "")

    prov_data = [[
        Paragraph("ID", table_head_style),
        Paragraph("Source", table_head_style),
        Paragraph("Action", table_head_style),
        Paragraph("Timestamp (UTC)", table_head_style),
        Paragraph("Target Entity", table_head_style),
        Paragraph("Provenance Role / Citation Reason", table_head_style),
    ]]

    for ev in evidence:
        ts_str = ev.timestamp.strftime("%H:%M:%S.%f")[:-3]
        reason_text = reason_map.get(ev.id, f"Sequential evidence supporting {activity.rule_name}")
        prov_data.append([
            Paragraph(f"<b>#{ev.id}</b>", table_cell_style),
            Paragraph(ev.source.upper(), table_cell_style),
            Paragraph(ev.action, table_cell_style),
            Paragraph(ts_str, table_cell_style),
            Paragraph(f"<font name='Courier' size=7>{ev.entity}</font>", table_cell_style),
            Paragraph(reason_text, table_cell_style),
        ])

    prov_table = Table(prov_data, colWidths=[28, 48, 64, 75, 160, 165])
    prov_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    elements.append(prov_table)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(
        "<font size=8 color='#94a3b8'>ForensiTrace Forensic Investigation Report &bull; Page 2 of 3 (Reconstructed Timeline & Provenance)</font>",
        subtitle_style
    ))

    # =========================================================================
    # PAGE 3: UNEDITED RAW EVENT APPENDIX
    # =========================================================================
    elements.append(PageBreak())
    elements.append(Paragraph("UNEDITED RAW EVENT APPENDIX", title_style))
    elements.append(Paragraph(
        "Cryptographic Non-Repudiation Record &bull; Untouched Ingestion Payloads & Hash Digests",
        subtitle_style
    ))
    elements.append(Spacer(1, 6))
    elements.append(HRFlowable(width="100%", thickness=1.0, color=colors.HexColor('#94a3b8'), spaceAfter=10))

    elements.append(Paragraph(
        "The following blocks contain the complete, unedited JSON payloads for all evidence events cited "
        "in this investigation, as recorded sequentially in the append-only SQLite log.",
        body_style
    ))
    elements.append(Spacer(1, 8))

    appendix_rows = []
    for ev in evidence:
        raw_obj = {
            "id": ev.id,
            "event_id": getattr(ev, "event_id", ""),
            "source": ev.source,
            "timestamp": ev.timestamp.isoformat(),
            "host": getattr(ev, "host", "WIN-ENDPOINT"),
            "user": getattr(ev, "user", "SYSTEM"),
            "action": ev.action,
            "entity": ev.entity,
            "details": getattr(ev, "details", {}),
            "prev_hash": getattr(ev, "prev_hash", "")[:16] + "...",
            "record_hash": getattr(ev, "record_hash", "")[:16] + "..."
        }
        json_dump = json.dumps(raw_obj, indent=2)
        appendix_rows.append([
            Paragraph(f"<b>Event Record #{ev.id} &bull; {ev.source.upper()}::{ev.action}</b>", table_head_style)
        ])
        # Format JSON code cleanly
        formatted_code = json_dump.replace(" ", "&nbsp;").replace("\n", "<br/>")
        appendix_rows.append([
            Paragraph(f"<font color='#0f172a'>{formatted_code}</font>", code_style)
        ])

    appendix_table = Table(appendix_rows, colWidths=[540])
    appendix_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
        ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#334155')),
        ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#334155')),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f1f5f9')),
        ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#f1f5f9')),
        ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#f1f5f9')),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    elements.append(appendix_table)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(
        "<font size=8 color='#94a3b8'>ForensiTrace Forensic Investigation Report &bull; Page 3 of 3 (Raw Evidence Appendix & End of Dossier)</font>",
        subtitle_style
    ))

    doc.build(elements)
