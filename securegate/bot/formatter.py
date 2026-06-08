"""Formats list[Finding] into a Markdown PR comment for SecureGate."""

from datetime import datetime, timezone
from typing import List, Optional

from securegate.finding_schema import Finding

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

    short_sha = (commit_sha or "")[:7]
    timestamp = scan_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append("")
    lines.append("---")
    lines.append(f"<sub>Commit `{short_sha}` · Scanned {timestamp} · SecureGate</sub>")

    return "\n".join(lines)
