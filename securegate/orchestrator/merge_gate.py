"""Sets the SecureGate pass/fail commit status that gates the PR merge."""

import os
from typing import List, Optional

import yaml
from github import Auth, Github

from securegate.finding_schema import Finding

# Shows up as the named status check on the PR.
STATUS_CONTEXT = "SecureGate/security-gate"

DEFAULT_POLICY = {
    "block_on_critical": True,
    "block_on_high": True,
    "block_on_medium": False,
    "suppress": [],
    "override_label": "security-override",
}


def _env(name: str) -> str:
    """Read a required environment variable or raise a clear error."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable {name!r}. "
            "SecureGate's merge gate expects GITHUB_TOKEN, REPO_NAME, "
            "PR_NUMBER and COMMIT_SHA (injected by GitHub Actions)."
        )
    return value


def load_policy(path: str = ".securegate.yml") -> dict:
    """Load policy from .securegate.yml, falling back to safe defaults."""
    policy = dict(DEFAULT_POLICY)
    try:
        with open(path) as fh:
            loaded = yaml.safe_load(fh) or {}
        policy.update(loaded)
    except FileNotFoundError:
        pass
    return policy


def _blocking_severities(policy: dict) -> set:
    """Severities that should block a merge, per policy flags."""
    blocking = set()
    if policy.get("block_on_critical"):
        blocking.add("CRITICAL")
    if policy.get("block_on_high"):
        blocking.add("HIGH")
    if policy.get("block_on_medium"):
        blocking.add("MEDIUM")
    return blocking


def evaluate(findings: List[Finding], policy: dict) -> List[Finding]:
    """Return the findings that violate policy and should block the merge.

    A finding blocks when its severity is in the blocking set, it is not in
    the suppress list, and it is not unreachable (reachable is not False).
    """
    blocking = _blocking_severities(policy)
    suppress = set(policy.get("suppress") or [])
    violations = []
    for f in findings:
        if (f.severity or "").upper() not in blocking:
            continue
        if f.id in suppress:
            continue
        if f.reachable is False:  # suppressed by reachability — don't gate
            continue
        violations.append(f)
    return violations


def _pr_has_override_label(pr, override_label: str) -> bool:
    if not override_label:
        return False
    return any(label.name == override_label for label in pr.get_labels())


def set_commit_status(
    findings: List[Finding],
    commit_sha: str,
    *,
    token: Optional[str] = None,
    repo_name: Optional[str] = None,
    pr_number: Optional[int] = None,
    policy_path: str = ".securegate.yml",
):
    """Set the SecureGate commit status (pass/fail) on the PR head commit.

    Args:
        findings: findings after reachability filtering (the same list the
            bot reports as actionable + suppressed).
        commit_sha: the commit to attach the status to.
        token / repo_name / pr_number: GitHub coordinates, default to the
            GITHUB_TOKEN / REPO_NAME / PR_NUMBER env vars.
        policy_path: path to .securegate.yml.

    Returns:
        The created PyGithub CommitStatus.

    A `security-override` label on the PR forces the status to success
    regardless of findings, so a human can consciously bypass the gate.
    """
    token = token or _env("GITHUB_TOKEN")
    repo_name = repo_name or _env("REPO_NAME")
    if pr_number is None:
        pr_number = int(_env("PR_NUMBER"))

    policy = load_policy(policy_path)
    violations = evaluate(findings, policy)

    auth = Auth.Token(token)
    client = Github(auth=auth)
    try:
        repo = client.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        commit = repo.get_commit(commit_sha)

        if violations and _pr_has_override_label(pr, policy.get("override_label")):
            return commit.create_status(
                state="success",
                context=STATUS_CONTEXT,
                description=(
                    f"{len(violations)} blocking finding(s) bypassed via "
                    f"'{policy.get('override_label')}' label"
                ),
            )

        if violations:
            return commit.create_status(
                state="failure",
                context=STATUS_CONTEXT,
                description=_failure_description(violations),
            )

        return commit.create_status(
            state="success",
            context=STATUS_CONTEXT,
            description="No blocking security findings",
        )
    finally:
        client.close()


def _failure_description(violations: List[Finding]) -> str:
    """Short status line, e.g. '2 blocking: 1 CRITICAL, 1 HIGH'."""
    counts = {}
    for f in violations:
        key = (f.severity or "").upper()
        counts[key] = counts.get(key, 0) + 1
    parts = [
        f"{counts[sev]} {sev}"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if counts.get(sev)
    ]
    # GitHub truncates status descriptions at 140 chars.
    return f"{len(violations)} blocking: " + ", ".join(parts)
