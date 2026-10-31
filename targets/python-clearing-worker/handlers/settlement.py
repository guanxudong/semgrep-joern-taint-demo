"""Settlement-file consumer."""
from ingest import parsers
from services import archive_service, recon_service


def on_settlement_file(event):
    text = event.read_text()
    header = parsers.parse_header(text)
    root = parsers.parse_settlement_xml(text.split("\n\n", 1)[1])
    rows = parsers.parse_records(text)
    recon_service._svc.set_operator(header.get("operator_role", "clerk"))
    if recon_service._svc.operator_role == "admin":
        recon_service._svc.admin_adjust(rows)
    else:
        recon_service._svc.apply_settlement(header.get("file_id", event.name), rows)
    attachment = header.get("attachment")
    if attachment:
        archive_service.import_attachment(attachment)
    return root


def on_settlement_file_safe(event):
    text = event.read_text()
    header = parsers.parse_header(text)
    root = parsers.parse_settlement_xml_safe(text.split("\n\n", 1)[1])
    attachment = header.get("attachment")
    if attachment:
        archive_service.import_attachment_safe(attachment)
    return root
