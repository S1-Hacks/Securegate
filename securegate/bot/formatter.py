"""Formats list[Finding] into a Markdown PR comment for SecureGate."""

import re
from datetime import datetime, timezone
from typing import List, Optional

from securegate.finding_schema import Finding
from securegate.reachability.cve_function_map import (
    get_functions_for_cve,
    get_functions_for_package,
)

# Marker so bot.py can find and update its existing comment on re-scan.
SECUREGATE_COMMENT_TAG = "<!-- securegate-bot -->"

SEVERITY_BADGES = {
    "CRITICAL": "CRITICAL 🔴",
    "HIGH": "HIGH 🟠",
    "MEDIUM": "MEDIUM 🟡",
    "LOW": "LOW 🔵",
}

# Highest first, for sorting findings within the table.
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _severity_badge(severity: str) -> str:
    """Return the emoji badge for a severity, falling back to the raw value."""
    key = (severity or "").upper()
    return SEVERITY_BADGES.get(key, severity or "UNKNOWN")


def _severity_rank(finding: Finding) -> int:
    return SEVERITY_ORDER.get((finding.severity or "").upper(), 99)


def _type_label(finding: Finding) -> str:
    """Human label for the finding's source (SAST = code, SCA = dependency)."""
    if finding.source == "SAST":
        return "SAST (code)"
    if finding.source == "SCA":
        return "SCA (dependency)"
    return finding.source or "—"


def _location(finding: Finding) -> str:
    """Where the finding lives: file:line for SAST, package@version for SCA."""
    if finding.file_path:
        if finding.line_number is not None:
            return f"`{finding.file_path}:{finding.line_number}`"
        return f"`{finding.file_path}`"
    if finding.package:
        version = finding.installed_version or "?"
        return f"`{finding.package}@{version}`"
    return "—"


def _fix(finding: Finding) -> str:
    """Suggested remediation: upgrade target for SCA, else a short hint."""
    if finding.fixed_version:
        pkg = finding.package or "package"
        return f"Upgrade `{pkg}` to `{finding.fixed_version}`"
    return "Review & patch — no fixed version available"


def _finding_name(finding: Finding) -> str:
    """Title cell, linked to the CVE/advisory when a URL is available."""
    title = finding.title or finding.id
    if finding.cve_url:
        return f"[{title}]({finding.cve_url})"
    return title


def _escape_cell(text: str) -> str:
    """Keep raw text from breaking Markdown table columns."""
    return text.replace("|", "\\|").replace("\n", " ")


def _table(findings: List[Finding]) -> str:
    """Render findings as a Markdown table sorted by severity (highest first)."""
    header = (
        "| Severity | Type | Finding | Location | Fix |\n"
        "| --- | --- | --- | --- | --- |"
    )
    rows = []
    for f in sorted(findings, key=_severity_rank):
        cells = [
            _severity_badge(f.severity),
            _type_label(f),
            _finding_name(f),
            _location(f),
            _fix(f),
        ]
        rows.append("| " + " | ".join(_escape_cell(c) for c in cells) + " |")
    return "\n".join([header, *rows])


def _summary_line(actionable: List[Finding]) -> str:
    """One-line tally of actionable findings by severity."""
    counts = {}
    for f in actionable:
        key = (f.severity or "").upper()
        counts[key] = counts.get(key, 0) + 1
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if counts.get(sev):
            parts.append(f"{counts[sev]} {_severity_badge(sev)}")
    return " · ".join(parts) if parts else "no actionable findings"


def _mid(text: str) -> str:
    """Sanitize text into a valid Mermaid node ID."""
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


def _mermaid_callgraph(
    actionable: List[Finding],
    suppressed: List[Finding],
) -> str:
    """Generate a Mermaid graph showing reachable vs suppressed vulnerable functions."""
    lines = [
        "```mermaid",
        "graph LR",
        "    classDef pkgNode  fill:#495057,color:#fff,stroke:#343a40",
        "    classDef critical fill:#dc3545,color:#fff,stroke:#dc3545",
        "    classDef high     fill:#fd7e14,color:#fff,stroke:#fd7e14",
        "    classDef medium   fill:#ffc107,color:#000,stroke:#ffc107",
        "    classDef suppNode fill:#28a745,color:#fff,stroke:#28a745",
        "    classDef sastNode fill:#6f42c1,color:#fff,stroke:#6f42c1",
    ]

    seen_pkg_nodes: set = set()

    def pkg_node(finding: Finding) -> str:
        """Emit a package node once and return its ID."""
        nid = _mid(f"pkg_{finding.package}_{finding.installed_version}")
        if nid not in seen_pkg_nodes:
            seen_pkg_nodes.add(nid)
            label = f"{finding.package}\\n@{finding.installed_version}"
            lines.append(f'    {nid}["{label}"]:::pkgNode')
        return nid

    # ── Reachable SCA findings ────────────────────────────────────────────────
    reachable_sca = [f for f in actionable if f.source == "SCA"]
    if reachable_sca:
        lines.append("    subgraph REACHABLE[\"🔴  Reachable — Action Required\"]")
        for f in reachable_sca:
            pnid = pkg_node(f)
            funcs = get_functions_for_cve(f.id or "") or \
                    get_functions_for_package(f.package or "")
            cve_nid = _mid(f"cve_{f.id}")
            sev_cls = "critical" if f.severity == "CRITICAL" else \
                      "high" if f.severity == "HIGH" else "medium"
            if funcs:
                for fn in funcs:
                    fn_nid = _mid(f"fn_reach_{f.package}_{fn}")
                    lines.append(f'    {fn_nid}(["{fn}()\\n🔴 called"]):::{sev_cls}')
                    lines.append(f"    {pnid} --> {fn_nid}")
                    lines.append(
                        f'    {fn_nid} --> {cve_nid}["{f.id}\\n{f.severity}"]:::{sev_cls}'
                    )
            else:
                lines.append(
                    f'    {pnid} --> {cve_nid}["{f.id}\\n{f.severity}"]:::{sev_cls}'
                )
        lines.append("    end")

    # ── Suppressed SCA findings ───────────────────────────────────────────────
    suppressed_sca = [f for f in suppressed if f.source == "SCA"]
    if suppressed_sca:
        lines.append("    subgraph SUPPRESSED[\"✅  Suppressed — Not Reachable\"]")
        for f in suppressed_sca:
            pnid = pkg_node(f)
            funcs = get_functions_for_cve(f.id or "") or \
                    get_functions_for_package(f.package or "")
            cve_nid = _mid(f"cve_sup_{f.id}")
            if funcs:
                for fn in funcs:
                    fn_nid = _mid(f"fn_sup_{f.package}_{fn}")
                    lines.append(f'    {fn_nid}(["{fn}()\\n✅ not called"]):::suppNode')
                    lines.append(f"    {pnid} -.-> {fn_nid}")
                    lines.append(
                        f'    {fn_nid} -.-> {cve_nid}["{f.id}\\nSuppressed"]:::suppNode'
                    )
            else:
                lines.append(
                    f'    {pnid} -.-> {cve_nid}["{f.id}\\nSuppressed"]:::suppNode'
                )
        lines.append("    end")

    # ── SAST findings ─────────────────────────────────────────────────────────
    sast = [f for f in actionable if f.source == "SAST"]
    if sast:
        lines.append("    subgraph SAST_BOX[\"⚡  SAST — Code Flaws\"]")
        for f in sast:
            short_file = (f.file_path or "unknown").split("/")[-1]
            file_nid = _mid(f"sast_file_{f.file_path}_{f.line_number}")
            rule_nid = _mid(f"sast_rule_{f.id}")
            sev_cls = "critical" if f.severity == "CRITICAL" else \
                      "high" if f.severity == "HIGH" else "sastNode"
            lines.append(
                f'    {file_nid}["{short_file}\\nline {f.line_number}"]:::sastNode'
            )
            lines.append(
                f'    {file_nid} --> {rule_nid}["{f.severity} code flaw"]:::{sev_cls}'
            )
        lines.append("    end")

    lines.append("```")
    return "\n".join(lines)


def format_pr_comment(
    actionable: List[Finding],
    suppressed: List[Finding],
    commit_sha: str,
    scan_time: Optional[datetime] = None,
) -> str:
    """Build the full Markdown PR comment.

    Args:
        actionable: findings the developer must act on (reachable / SAST).
        suppressed: findings filtered out by reachability (reachable=False),
            shown in a collapsible section for transparency.
        commit_sha: the commit the scan ran against.
        scan_time: timestamp of the scan (defaults to now, UTC).

    Returns:
        Markdown string, prefixed with SECUREGATE_COMMENT_TAG so the bot can
        locate and update it on re-scan.
    """
    if scan_time is None:
        scan_time = datetime.now(timezone.utc)

    lines = [SECUREGATE_COMMENT_TAG, "## 🛡️ SecureGate Security Report", ""]

    if actionable:
        lines.append(f"**{len(actionable)} actionable finding(s):** {_summary_line(actionable)}")
        lines.append("")
        lines.append(_table(actionable))
    else:
        lines.append("✅ **No actionable security findings.** Good to merge.")

    if suppressed:
        lines.append("")
        lines.append("<details>")
        lines.append(
            f"<summary>🔇 {len(suppressed)} finding(s) suppressed as unreachable</summary>"
        )
        lines.append("")
        lines.append(
            "These vulnerabilities exist in dependencies but the vulnerable "
            "code paths are not reachable from this project."
        )
        lines.append("")
        lines.append(_table(suppressed))
        lines.append("")
        lines.append("</details>")

    # ── Call graph visualisation ──────────────────────────────────────────────
    if actionable or suppressed:
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>🕸️ Reachability Call Graph</summary>")
        lines.append("")
        lines.append(_mermaid_callgraph(actionable, suppressed))
        lines.append("")
        lines.append("</details>")

    short_sha = (commit_sha or "")[:7]
    timestamp = scan_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append("")
    lines.append("---")
    lines.append(f"<sub>Commit `{short_sha}` · Scanned {timestamp} · SecureGate</sub>")

    return "\n".join(lines)
