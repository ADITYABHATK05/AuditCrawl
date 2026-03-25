from __future__ import annotations

import json
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring


def export_findings(run_id: int, payload: dict, output_dir: str) -> tuple[str, str]:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"run_{run_id}.json"
    xml_path = out_dir / f"run_{run_id}.xml"

    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    root = Element("scanResult")
    SubElement(root, "runId").text = str(run_id)
    SubElement(root, "targetUrl").text = payload.get("target_url", "")
    SubElement(root, "scanLevel").text = payload.get("scan_level", "")

    findings_el = SubElement(root, "findings")
    for finding in payload.get("findings", []):
        item = SubElement(findings_el, "finding")
        for key in [
            "vulnerability_type",
            "severity",
            "endpoint",
            "evidence",
            "vulnerable_snippet",
            "fix_snippet",
        ]:
            SubElement(item, key).text = str(finding.get(key, ""))

    xml_path.write_bytes(tostring(root, encoding="utf-8", xml_declaration=True))
    return str(json_path), str(xml_path)
