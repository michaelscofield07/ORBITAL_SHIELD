"""
Audit Service — Report Generator

Exports an incident's audit record as a formatted PDF,
suitable for compliance/regulatory submission.
"""

from fastapi import APIRouter, HTTPException, Response
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from schemas import SecurityEvent
from storage import get_all_records

router = APIRouter()

REPORTS_DIR = Path(__file__).resolve().parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


@router.get("/audit/{event_id}/report")
def generate_report(event_id: str):
    records = get_all_records()
    record = next((r for r in records if r["event_id"] == event_id), None)

    if not record:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

    event = SecurityEvent.model_validate_json(record["event_json"])

    output_path = REPORTS_DIR / f"incident_{event_id}.pdf"
    
    # Setup document with tighter margins
    doc = SimpleDocTemplate(
        str(output_path), 
        pagesize=letter,
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = styles["Title"]
    title_style.textColor = colors.HexColor("#1e293b")
    
    h1_style = styles["Heading1"]
    h1_style.textColor = colors.HexColor("#0f172a")
    h1_style.spaceAfter = 10
    
    normal_style = styles["Normal"]
    normal_style.fontSize = 10
    normal_style.leading = 14
    
    story = []

    # Header
    story.append(Paragraph("ORBITAL SHIELD SECURITY OPERATIONS", h1_style))
    story.append(Paragraph("CONFIDENTIAL INCIDENT REPORT", title_style))
    story.append(Spacer(1, 20))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary", h1_style))
    summary_text = (
        f"On {event.timestamp.strftime('%Y-%m-%d at %H:%M:%S UTC')}, the Orbital Shield monitoring system "
        f"detected a {event.severity.value.lower()}-severity security anomaly (ID: {event.event_id}). "
        f"The incident was flagged by the {event.source} subsystem with a confidence rating of {round(event.confidence * 100)}%. "
        f"Automated protocols initiated a {event.action.value} response. The current investigative status is marked as {record['review_status']}."
    )
    story.append(Paragraph(summary_text, normal_style))
    story.append(Spacer(1, 20))

    # Incident Details Table
    story.append(Paragraph("2. Incident Specifications", h1_style))
    details = [
        ["Attribute", "Value"],
        ["Incident ID", event.event_id],
        ["Target Satellite", event.satellite_id or "N/A"],
        ["Detection Source", event.source],
        ["Event Classification", event.event_type.replace('_', ' ').title()],
        ["Severity Level", event.severity.value],
        ["Response Action", event.action.value],
        ["Correlated Events", ", ".join(event.related_events) if event.related_events else "None Detected"],
    ]

    table = Table(details, colWidths=[150, 350])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))

    # Technical Description
    story.append(Paragraph("3. Technical Description", h1_style))
    story.append(Paragraph(event.description, normal_style))
    story.append(Spacer(1, 20))

    # Cryptographic Audit Trail
    story.append(Paragraph("4. Cryptographic Audit Trail", h1_style))
    story.append(Paragraph("This record is mathematically bound to the Orbital Shield immutable ledger.", normal_style))
    story.append(Spacer(1, 10))
    
    crypto_data = [
        ["Cryptographic Hash (SHA-256)", record['record_hash']],
        ["Previous Block Hash", record['previous_hash']],
        ["Ledger Timestamp", record['stored_at']],
    ]
    crypto_table = Table(crypto_data, colWidths=[150, 350])
    crypto_table.setStyle(TableStyle([
        ("FONTNAME", (1, 0), (1, -1), "Courier"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(crypto_table)
    story.append(Spacer(1, 50))

    # Sign-off Block
    story.append(Paragraph("5. Authorization & Sign-off", h1_style))
    story.append(Spacer(1, 30))
    
    sign_data = [
        ["___________________________________", "___________________________________"],
        ["Incident Commander Signature", "System Auditor Signature"],
        ["Date: ________________________", "Date: ________________________"]
    ]
    sign_table = Table(sign_data, colWidths=[250, 250])
    sign_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(sign_table)

    doc.build(story)

    with open(str(output_path), "rb") as f:
        pdf_bytes = f.read()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="incident_{event_id}.pdf"'}
    )