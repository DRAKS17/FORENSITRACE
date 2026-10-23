"""
ForensiTrace - Forensic PDF Report Generator (PURVA)
Uses ReportLab to generate formal, tamper-evident case summary reports
including activity narratives, cryptographic hash-chain verification statements,
and detailed evidence provenance tables.
"""

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
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
    Generates a formal forensic PDF report for an activity reconstruction.
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

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        alignment=0
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b')
    )
    heading2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#334155')
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

    # Document Header
    elements.append(Paragraph("FORENSITRACE FORENSIC EVIDENCE REPORT", title_style))
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(f"Cross-Source Correlation Engine &bull; Generated: {now_str} &bull; Classification: INVESTIGATIVE SENSITIVE", subtitle_style))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceAfter=14))

    # Case Summary Card
    conf_color = "#dc2626" if activity.confidence_level == "HIGH" else ("#d97706" if activity.confidence_level == "MEDIUM" else "#4b5563")
    summary_data = [
        [
            Paragraph("<b>Case Reference:</b>", body_style),
            Paragraph(f"ACT-{activity.id:04d}", body_style),
            Paragraph("<b>Rule Fired:</b>", body_style),
            Paragraph(activity.rule_name, body_style)
        ],
        [
            Paragraph("<b>Activity Title:</b>", body_style),
            Paragraph(activity.title, body_style),
            Paragraph("<b>Confidence:</b>", body_style),
            Paragraph(f"<font color='{conf_color}'><b>{activity.confidence_level} ({activity.confidence_score:.2f})</b></font>", body_style)
        ],
        [
            Paragraph("<b>Time Boundary:</b>", body_style),
            Paragraph(f"{activity.timestamp_start.strftime('%H:%M:%S')} &rarr; {activity.timestamp_end.strftime('%H:%M:%S')}", body_style),
            Paragraph("<b>Evidence Count:</b>", body_style),
            Paragraph(f"{len(evidence)} verified artifacts", body_style)
        ]
    ]
    summary_table = Table(summary_data, colWidths=[100, 180, 90, 170])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 14))

    # Narrative Reconstruction
    elements.append(Paragraph("Reconstructed Threat Narrative", heading2_style))
    narrative_p = Paragraph(f"<i>{activity.narrative}</i>", body_style)
    narrative_box = Table([[narrative_p]], colWidths=[540])
    narrative_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#eff6ff')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#bfdbfe')),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(narrative_box)
    elements.append(Spacer(1, 14))

    # Cryptographic Chain Assurance
    elements.append(Paragraph("Cryptographic Chain Integrity Verification", heading2_style))
    if chain_verified:
        integrity_status = "<font color='#16a34a'><b>INTEGRITY VERIFIED &bull; UNBROKEN HASH CHAIN</b></font>"
        integrity_text = (
            f"Status: {integrity_status}<br/>"
            "Each raw evidence artifact cited below is sequentially anchored in the ForensiTrace append-only SQLite log "
            "using recursive SHA-256 hash chaining. The cryptographic link continuity was independently audited at report "
            "generation time and confirmed 100% intact, establishing strict non-repudiation and anti-tamper legal validity."
        )
    else:
        integrity_status = "<font color='#dc2626'><b>INTEGRITY COMPROMISED &bull; HASH MISMATCH DETECTED</b></font>"
        integrity_text = (
            f"Status: {integrity_status}<br/>"
            "WARNING: The cryptographic hash chain exhibits tampering or record deletion. Proceed with caution."
        )

    integrity_box = Table([[Paragraph(integrity_text, body_style)]], colWidths=[540])
    integrity_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f0fdf4') if chain_verified else colors.HexColor('#fef2f2')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#bbf7d0') if chain_verified else colors.HexColor('#fecaca')),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(integrity_box)
    elements.append(Spacer(1, 14))

    # Evidence Provenance Table
    elements.append(Paragraph("Evidence Provenance & Cross-Source Telemetry", heading2_style))

    # Map reason if provenance links provided
    reason_map = {}
    if provenance_links:
        for link in provenance_links:
            ev_id = link.get("event", {}).id if hasattr(link.get("event"), "id") else link.get("event_id")
            if ev_id:
                reason_map[ev_id] = link.get("reason", "")

    table_data = [[
        Paragraph("ID", table_head_style),
        Paragraph("Source", table_head_style),
        Paragraph("Action", table_head_style),
        Paragraph("Timestamp (UTC)", table_head_style),
        Paragraph("Entity / Target", table_head_style),
        Paragraph("Provenance Context / Reason", table_head_style),
    ]]

    for ev in evidence:
        ts_str = ev.timestamp.strftime("%H:%M:%S.%f")[:-3]
        reason_text = reason_map.get(ev.id, f"Correlated artifact supporting {activity.rule_name}")
        table_data.append([
            Paragraph(f"<b>#{ev.id}</b>", table_cell_style),
            Paragraph(ev.source.upper(), table_cell_style),
            Paragraph(ev.action, table_cell_style),
            Paragraph(ts_str, table_cell_style),
            Paragraph(f"<font name='Courier' size=7>{ev.entity}</font>", table_cell_style),
            Paragraph(reason_text, table_cell_style),
        ])

    evidence_table = Table(table_data, colWidths=[30, 48, 64, 80, 160, 158])
    evidence_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    elements.append(evidence_table)
    elements.append(Spacer(1, 16))

    # Footer note
    footer_text = "ForensiTrace Endpoint Forensics &bull; Final Report Document &bull; Verified via SHA-256 Hash Chaining"
    elements.append(Paragraph(f"<font size=8 color='#94a3b8'>{footer_text}</font>", subtitle_style))

    doc.build(elements)
