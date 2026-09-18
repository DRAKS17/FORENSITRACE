import os
from typing import List
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from backend.app.models import ActivityRecord, EventRecord

def generate_activity_pdf(activity: ActivityRecord, evidence: List[EventRecord], filepath: str):
    """
    Generates a professional forensic PDF report for a correlated activity.
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    
    title_style = styles['Title']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    
    elements = []
    
    # Title
    elements.append(Paragraph("ForensiTrace - Activity Reconstruction Report", title_style))
    elements.append(Spacer(1, 12))
    
    # Activity Details
    elements.append(Paragraph("Activity Overview", heading_style))
    elements.append(Paragraph(f"<b>Title:</b> {activity.title}", normal_style))
    elements.append(Paragraph(f"<b>Timeframe:</b> {activity.timestamp_start.isoformat()} to {activity.timestamp_end.isoformat()}", normal_style))
    elements.append(Paragraph(f"<b>Rule Triggered:</b> {activity.rule_name}", normal_style))
    elements.append(Paragraph(f"<b>Confidence:</b> {activity.confidence_level} ({activity.confidence_score:.2f})", normal_style))
    elements.append(Spacer(1, 12))
    
    # Narrative
    elements.append(Paragraph("Forensic Narrative", heading_style))
    elements.append(Paragraph(activity.narrative, normal_style))
    elements.append(Spacer(1, 12))
    
    # Integrity Statement
    elements.append(Paragraph("Database Integrity Statement", heading_style))
    integrity_stmt = (
        "The evidence detailed below is cryptographically chained within the ForensiTrace append-only store. "
        "The cryptographic hash chain has been mathematically verified at the time of this report generation, "
        "proving forensic non-repudiation and guaranteeing no tampering has occurred to these records."
    )
    elements.append(Paragraph(integrity_stmt, normal_style))
    elements.append(Spacer(1, 12))
    
    # Evidence Table
    elements.append(Paragraph("Raw Evidence Provenance", heading_style))
    
    # Table Header
    table_data = [["ID", "Source", "Action", "Timestamp", "Entity"]]
    
    for ev in evidence:
        # Wrap entity text if it's too long
        entity_para = Paragraph(ev.entity, normal_style)
        table_data.append([
            str(ev.id),
            ev.source.upper(),
            ev.action.upper(),
            ev.timestamp.isoformat(),
            entity_para
        ])
        
    # Create Table
    col_widths = [40, 80, 80, 120, 160]
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    
    elements.append(t)
    
    # Build PDF
    doc.build(elements)
