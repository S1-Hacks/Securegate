"""Posts (or updates) the SecureGate security report as a PR comment."""

import os
from typing import List, Optional

from github import Auth, Github

from securegate.bot.formatter import SECUREGATE_COMMENT_TAG, format_pr_comment
from securegate.finding_schema import Finding


def _env(name: str) -> str:
    """Read a required environment variable or raise a clear error."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable {name!r}. "
            "SecureGate's bot expects GITHUB_TOKEN, REPO_NAME and PR_NUMBER "
            "(injected by GitHub Actions)."
        )
    return value


def _find_existing_comment(pr):
    """Return the bot's previous comment on this PR, or None on first run."""
    for comment in pr.get_issue_comments():
        if SECUREGATE_COMMENT_TAG in (comment.body or ""):
            return comment
    return None


def post_pr_comment(
    actionable: List[Finding],
    suppressed: List[Finding],
    commit_sha: str,
    *,
    token: Optional[str] = None,
    repo_name: Optional[str] = None,
    pr_number: Optional[int] = None,
):
    """Post the SecureGate report to the PR, updating in place on re-scan.

    Args:
        actionable: findings the developer must act on (reachable / SAST).
        suppressed: findings filtered out by reachability (reachable=False).
        commit_sha: the commit the scan ran against.
        token: GitHub token (defaults to GITHUB_TOKEN env var).
        repo_name: "owner/repo" (defaults to REPO_NAME env var).
        pr_number: pull request number (defaults to PR_NUMBER env var).

    Returns:
        The created or edited PyGithub IssueComment.

    The comment is tagged with SECUREGATE_COMMENT_TAG so subsequent scans
    find and edit the same comment instead of stacking duplicates.
    """
    token = token or _env("GITHUB_TOKEN")
    repo_name = repo_name or _env("REPO_NAME")
    if pr_number is None:
        pr_number = int(_env("PR_NUMBER"))

    body = format_pr_comment(actionable, suppressed, commit_sha)

    auth = Auth.Token(token)
    client = Github(auth=auth)
    try:
        repo = client.get_repo(repo_name)
        pr = repo.get_pull(pr_number)

        existing = _find_existing_comment(pr)
        if existing is not None:
            existing.edit(body)
            return existing
        return pr.create_issue_comment(body)
    finally:
        client.close()
