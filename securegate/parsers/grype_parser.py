import json
from typing import List, Optional
from securegate.finding_schema import Finding

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "negligible": "LOW",
    "unknown": "LOW",
}


def _map_severity(grype_severity: str) -> str:
    return _SEVERITY_MAP.get(grype_severity.lower(), "LOW")


def _nvd_url(urls: list) -> Optional[str]:
    for url in urls:
        if "nvd.nist.gov" in url:
            return url
    return urls[0] if urls else None


def parse_grype(json_path: str) -> List[Finding]:
    with open(json_path) as f:
        data = json.load(f)

    findings = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        related = match.get("relatedVulnerabilities", [])

        # Prefer CVE ID from relatedVulnerabilities (GHSA entries point to a CVE there)
        finding_id = vuln.get("id", "unknown")
        for rv in related:
            if rv.get("id", "").startswith("CVE-"):
                finding_id = rv["id"]
                break

        fix_versions = vuln.get("fix", {}).get("versions", [])
        fixed_version = fix_versions[0] if fix_versions else None

        all_urls = vuln.get("urls", [])
        cve_url = _nvd_url(all_urls)

        package_name = artifact.get("name", "unknown")
        title = f"{package_name} {finding_id}"

        findings.append(Finding(
            id=finding_id,
            title=title,
            severity=_map_severity(vuln.get("severity", "unknown")),
            source="SCA",
            file_path=None,
            line_number=None,
            package=package_name,
            installed_version=artifact.get("version"),
            fixed_version=fixed_version,
            description=vuln.get("description", ""),
            reachable=None,
            cve_url=cve_url,
        ))

    return findings
