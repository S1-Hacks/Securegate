import json
from typing import List
from securegate.finding_schema import Finding

_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "NOTE": "LOW",
}


def _map_severity(semgrep_severity: str) -> str:
    return _SEVERITY_MAP.get(semgrep_severity.upper(), "MEDIUM")


def parse_semgrep(json_path: str) -> List[Finding]:
    with open(json_path) as f:
        data = json.load(f)

    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        # Prefer CVE from metadata, fall back to rule ID
        cve_list = metadata.get("cve", [])
        finding_id = cve_list[0] if cve_list else result.get("check_id", "unknown")

        severity = _map_severity(extra.get("severity", "INFO"))

        # Bump to CRITICAL if metadata signals it
        if metadata.get("impact", "").upper() == "CRITICAL":
            severity = "CRITICAL"

        cve_url = (
            metadata.get("shortlink")
            or metadata.get("source")
            or None
        )

        findings.append(Finding(
            id=finding_id,
            title=result.get("check_id", "unknown"),
            severity=severity,
            source="SAST",
            file_path=result.get("path"),
            line_number=result.get("start", {}).get("line"),
            package=None,
            installed_version=None,
            fixed_version=None,
            description=extra.get("message", ""),
            reachable=True,
            cve_url=cve_url,
        ))

    return findings
