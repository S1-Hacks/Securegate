"""
dedup.py — collapse duplicate findings so each issue is surfaced exactly once.

Two kinds of duplication are removed:
  * Cross-source CVE: the same CVE id reported by BOTH SAST and SCA. We keep the SCA
    record (it carries package + installed/fixed version = the actionable fix) but mark it
    reachable=True, because a SAST hit is direct proof the code path is reachable.
  * Exact duplicates: identical rows within a single source (same id + location/package).

Order is preserved (first occurrence wins its slot) for stable, readable PR comments.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Sequence

if TYPE_CHECKING:  # pragma: no cover
    from securegate.finding_schema import Finding

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def _is_cve(value: str) -> bool:
    return bool(_CVE_RE.match((value or "").strip()))


def _exact_key(f) -> tuple:
    """Identity for exact-duplicate detection within a source."""
    return (
        (getattr(f, "id", "") or "").strip().upper(),
        (getattr(f, "source", "") or "").strip().upper(),
        getattr(f, "file_path", None),
        getattr(f, "line_number", None),
        (getattr(f, "package", "") or "").strip().lower(),
    )


def deduplicate(findings: Sequence["Finding"]) -> List["Finding"]:
    """Return a de-duplicated list, preserving first-seen order.

    Safe on empty/None input. Does not mutate inputs except to set reachable=True on a
    surviving CVE record when its twin proves reachability.
    """
    findings = list(findings or [])
    if not findings:
        return findings

    # Pass 1: drop exact duplicates.
    seen_exact = set()
    unique: List["Finding"] = []
    for f in findings:
        key = _exact_key(f)
        if key in seen_exact:
            continue
        seen_exact.add(key)
        unique.append(f)

    # Pass 2: collapse the same CVE id appearing across SAST and SCA into one row.
    by_cve: dict = {}          # normalised CVE id -> index in `result`
    result: List["Finding"] = []
    for f in unique:
        cve_id = (getattr(f, "id", "") or "").strip().upper()
        source = (getattr(f, "source", "") or "").strip().upper()

        if not _is_cve(cve_id):
            result.append(f)    # non-CVE (e.g. Semgrep rule id) — never cross-collapsed
            continue

        if cve_id not in by_cve:
            by_cve[cve_id] = len(result)
            result.append(f)
            continue

        # Duplicate CVE across sources: keep the richer record, merge reachability.
        existing = result[by_cve[cve_id]]
        existing_is_sca = (getattr(existing, "source", "") or "").upper() == "SCA"
        new_is_sca = source == "SCA"

        # Prefer the SCA record (has package/version/fix). If we already kept SAST and now
        # see SCA, swap to the SCA one but remember it was reachable.
        if new_is_sca and not existing_is_sca:
            f.reachable = True  # SAST twin proves reachability
            result[by_cve[cve_id]] = f
        else:
            # Either existing is SCA (keep it) or both same source; a SAST twin => reachable.
            if not new_is_sca or not existing_is_sca:
                existing.reachable = True

    return result
