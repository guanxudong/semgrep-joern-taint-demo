"""Settlement-file parsers: pipe-delimited header records and XML payloads."""
from lxml import etree


def parse_header(text):
    """Parse the first pipe-delimited header line into a dict."""
    header = {}
    for field in text.splitlines()[0].split("|"):
        if "=" in field:
            key, _, value = field.partition("=")
            header[key.strip()] = value.strip()
    return header


def parse_settlement_xml(raw):
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.fromstring(raw, parser=parser)


def parse_settlement_xml_safe(raw):
    from defusedxml import ElementTree
    return ElementTree.fromstring(raw)


def parse_records(text):
    """Parse fixed-width settlement records after the header line."""
    records = []
    for line in text.splitlines()[1:]:
        if not line.strip():
            continue
        records.append({
            "account": line[0:10].strip(),
            "symbol": line[10:22].strip(),
            "settled": float(line[22:36]),
            "expected": float(line[36:50]),
        })
    return records
