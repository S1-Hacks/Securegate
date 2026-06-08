"""
Orchestrator: reads scan artifacts, applies reachability filtering,
triggers the PR bot and merge gate.

Expected env vars (injected by GitHub Actions):
  GITHUB_TOKEN, REPO_NAME, PR_NUMBER, COMMIT_SHA

Scan artifact paths (defaults match CI artifact names):
  SAST_RESULTS  — path to semgrep JSON  (default: sast-results.json)
  SCA_RESULTS   — path to grype JSON    (default: sca-results.json)
  SOURCE_DIR    — repo root for call-graph analysis (default: .)
"""

import os
import sys
from typing import List, Tuple

from securegate.parsers.semgrep_parser import parse_semgrep
from securegate.parsers.grype_parser import parse_grype
from securegate.finding_schema import Finding

# ── Dev 2: reachability engine ────────────────────────────────────────────────
try:
    from securegate.reachability.reachability import apply_reachability
    _HAS_REACHABILITY = True
except ImportError:
    _HAS_REACHABILITY = False

# ── Dev 3: bot + merge gate ───────────────────────────────────────────────────
try:
    from securegate.bot.bot import post_pr_comment
    from securegate.orchestrator.merge_gate import set_commit_status
    _HAS_BOT = True
except ImportError:
    _HAS_BOT = False


def _split(findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
    """Split findings into actionable (reachable != False) and suppressed."""
    actionable = [f for f in findings if f.reachable is not False]
    suppressed = [f for f in findings if f.reachable is False]
    return actionable, suppressed


def _stub_reachability(findings: List[Finding], source_dir: str) -> List[Finding]:
    """Fallback: mark SAST always reachable, SCA unknown until Dev 2 merges."""
    for f in findings:
        if f.source == "SAST":
            f.reachable = True
        # SCA stays None (unknown) — no filtering without Dev 2
    return findings


def _print_summary(actionable: List[Finding], suppressed: List[Finding], commit_sha: str) -> None:
    """Fallback output when Dev 3 bot is not yet available."""
    print(f"\n{'='*60}")
    print(f"SecureGate scan summary  |  commit: {commit_sha}")
    print(f"{'='*60}")
    print(f"Actionable findings : {len(actionable)}")
    print(f"Suppressed findings : {len(suppressed)}")
    for f in actionable:
        print(f"  [{f.severity:8s}] [{f.source}] {f.id} — {f.title[:60]}")
    if suppressed:
        print(f"\nSuppressed ({len(suppressed)}):")
        for f in suppressed:
            print(f"  [SUPPRESSED] {f.id}")
    print(f"{'='*60}\n")


def run(
    sast_path: str,
    sca_path: str,
    source_dir: str,
    commit_sha: str,
) -> int:
    """
    Core orchestration logic. Returns exit code:
      0 = scan passed / no blocking findings
      1 = merge should be blocked
    """
    # ── 1. Parse scan artifacts ───────────────────────────────────────────────
    sast_findings = parse_semgrep(sast_path) if os.path.exists(sast_path) else []
    sca_findings = parse_grype(sca_path) if os.path.exists(sca_path) else []

    if not sast_findings and not sca_findings:
        print("[securegate] No scan results found — ensure scan jobs ran first.")
        return 0

    all_findings = sast_findings + sca_findings
    print(f"[securegate] Parsed {len(sast_findings)} SAST + {len(sca_findings)} SCA findings.")

    # ── 2. Reachability filtering ─────────────────────────────────────────────
    if _HAS_REACHABILITY:
        all_findings = apply_reachability(all_findings, source_dir)
        print(f"[securegate] Reachability applied via Dev 2 engine.")
    else:
        all_findings = _stub_reachability(all_findings, source_dir)
        print(f"[securegate] Reachability engine not available — using stub.")

    # ── 3. Split actionable vs suppressed ─────────────────────────────────────
    actionable, suppressed = _split(all_findings)
    print(f"[securegate] Actionable: {len(actionable)} | Suppressed: {len(suppressed)}")

    # ── 4. Post PR comment ────────────────────────────────────────────────────
    if _HAS_BOT:
        post_pr_comment(actionable, suppressed, commit_sha)
        print(f"[securegate] PR comment posted.")
    else:
        _print_summary(actionable, suppressed, commit_sha)

    # ── 5. Set commit status / merge gate ─────────────────────────────────────
    if _HAS_BOT:
        blocked = set_commit_status(actionable, commit_sha)
        return 1 if blocked else 0

    # Fallback gate: block if any CRITICAL or HIGH actionable finding
    severities = {f.severity for f in actionable}
    if "CRITICAL" in severities or "HIGH" in severities:
        print("[securegate] MERGE BLOCKED — CRITICAL or HIGH findings present.")
        return 1

    print("[securegate] Merge gate: PASSED.")
    return 0


def main() -> None:
    sast_path = os.getenv("SAST_RESULTS", "sast-results.json")
    sca_path = os.getenv("SCA_RESULTS", "sca-results.json")
    source_dir = os.getenv("SOURCE_DIR", ".")
    commit_sha = os.getenv("COMMIT_SHA", "local")

    exit_code = run(sast_path, sca_path, source_dir, commit_sha)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
