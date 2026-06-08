# SecureGate — Claude Code Context

## What this project is
A CI-native security tool that scans every PR for vulnerabilities using SAST (Semgrep) + SCA (Grype),
filters noise with reachability analysis, posts findings as PR comments, and blocks high-risk merges.
This is a one-day hackathon sprint split across three devs working in parallel branches.

## Critical file to read first
`securegate/finding_schema.py` — the shared Finding dataclass. Every module produces or consumes this.
Never change this schema without syncing with the team.

## Branch ownership
- `feature/scanning-pipeline` → Dev 1
- `feature/reachability-engine` → Dev 2
- `feature/pr-bot-and-gates` → Dev 3
- `main` → base structure only; orchestrator.py merged here at EOD

---

## Dev 1 — feature/scanning-pipeline

### Files you own
- `.github/workflows/securegate.yml`
- `securegate/parsers/semgrep_parser.py`
- `securegate/parsers/grype_parser.py`
- `securegate/orchestrator/orchestrator.py`

### Your full task list (one day)
1. Set up GitHub Actions workflow — trigger on PR open/push, three jobs: sast-scan, sca-scan, orchestrate
2. Install and configure Semgrep with p/security-audit + p/owasp-top-ten + p/secrets rulesets
3. Install Grype, point at demo-repo/package.json and demo-repo/requirements.txt
4. Write semgrep_parser.py — parse Semgrep JSON output into list[Finding]
5. Write grype_parser.py — parse Grype JSON output into list[Finding]
6. Build orchestrator.py — calls parsers, passes findings to reachability engine, triggers bot
7. Add scan result caching — skip re-scan if dependency manifest unchanged
8. Run end-to-end smoke test: open a PR with demo-repo changes, confirm scan completes under 3 min

### How your output connects to others
- Your parsers output list[Finding] → Dev 2 consumes this for reachability filtering
- Your orchestrator.py calls Dev 2's apply_reachability() and Dev 3's post_pr_comment() and set_commit_status()
- Coordinate with Dev 2 in first 30 min to confirm Finding schema — do not change finding_schema.py unilaterally

### Local test commands
```bash
semgrep --config p/security-audit --config p/secrets --json demo-repo/src/ > sast-results.json
grype dir:demo-repo --output json > sca-results.json
python -c "from securegate.parsers.semgrep_parser import parse_semgrep; print(parse_semgrep('sast-results.json'))"
```

---

## Dev 2 — feature/reachability-engine

### Files you own
- `securegate/reachability/callgraph_builder.py`
- `securegate/reachability/reachability.py`
- `securegate/reachability/cve_function_map.py`
- `securegate/reachability/dedup.py`
- `tests/test_reachability.py`

### Your full task list (one day)
1. Set up pycg (Python call graph) and js-callgraph (Node call graph) as backends in callgraph_builder.py
2. Build cve_function_map.py — hardcode CVE ID → vulnerable function name for all seeded demo CVEs:
   - CVE-2021-23337 → lodash → template()
   - CVE-2022-24999 → express → send()
   - CVE-2021-34552 → Pillow → frombytes(), crop()
   - CVE-2023-32681 → requests → get(), post()
3. Build reachability.py — apply_reachability(findings, source_dir): marks each SCA finding reachable=True/False
4. Write dedup.py — if same CVE appears in both SAST and SCA output, surface it only once
5. Harden against edge cases: circular imports, dynamic requires, missing call graph output
6. Write unit tests in tests/test_reachability.py:
   - test that a finding whose function IS in the call graph → reachable=True
   - test that a finding whose function is NOT in call graph → reachable=False
7. Validate on demo-repo: confirm at least 60% of raw SCA findings get suppressed

### How your output connects to others
- You consume list[Finding] from Dev 1's parsers
- You return filtered list[Finding] back to Dev 1's orchestrator.py
- SAST findings must always be marked reachable=True — never filter them
- Coordinate with Dev 1 in first 30 min to confirm Finding schema

### Local test commands
```bash
pip install pycg
npm install -g js-callgraph
python -m pytest tests/test_reachability.py -v
```

---

## Dev 3 — feature/pr-bot-and-gates

### Files you own
- `securegate/bot/formatter.py`
- `securegate/bot/bot.py`
- `securegate/orchestrator/merge_gate.py`
- `.securegate.yml`

### Your full task list (one day)
1. Build formatter.py — formats list[Finding] into a Markdown PR comment with:
   - Severity badges: CRITICAL 🔴, HIGH 🟠, MEDIUM 🟡, LOW 🔵
   - Table: Severity | Type | Finding | Location | Fix
   - Collapsible section for suppressed findings (reachable=False)
   - Footer showing commit SHA and scan timestamp
2. Build bot.py — post_pr_comment(actionable, suppressed, commit_sha):
   - Uses PyGithub to post comment on the PR
   - Uses SECUREGATE_COMMENT_TAG to find and update existing comment on re-scan (no duplicate comments)
3. Build merge_gate.py — set_commit_status(findings, commit_sha):
   - Calls GitHub Checks API to set pass/fail on the PR
   - Reads policy from .securegate.yml (block_on_critical, block_on_high)
   - Implements security-override label bypass logic
4. Polish .securegate.yml — ensure block_on_critical, block_on_high, suppress list, override_label all work
5. Rehearse the full demo narrative end-to-end:
   - Open PR with seeded vuln → pipeline triggers → bot comment appears → merge blocked
   - Fix the vuln → pipeline re-runs → comment updates → merge unblocked

### How your output connects to others
- You consume list[Finding] from Dev 1's orchestrator (after Dev 2's reachability filter is applied)
- Dev 1's orchestrator.py calls your post_pr_comment() and set_commit_status() — agree on function signatures early
- Required env vars your code reads: GITHUB_TOKEN, REPO_NAME, PR_NUMBER, COMMIT_SHA (all injected by GitHub Actions)

### Local test commands
```bash
pip install PyGithub pyyaml
python -c "
from securegate.finding_schema import Finding
from securegate.bot.formatter import format_pr_comment
f = Finding('CVE-2021-23337','lodash template injection','HIGH','SCA',None,None,'lodash','4.17.15','4.17.21','Command injection',True,'https://nvd.nist.gov/vuln/detail/CVE-2021-23337')
print(format_pr_comment([f], [], 'abc1234'))
"
```

---

## End of day integration order
1. Dev 2 merges feature/reachability-engine → main first (no dependencies on others)
2. Dev 3 merges feature/pr-bot-and-gates → main second
3. Dev 1 merges feature/scanning-pipeline → main last (orchestrator.py wires everything together)
4. Allocate 30-45 min for conflict resolution in orchestrator.py imports
5. Run full end-to-end test on merged main before demo

## Running scanners locally (for testing)
```bash
semgrep --config p/security-audit --json demo-repo/src/ > sast-results.json
grype dir:demo-repo --output json > sca-results.json
```

## Install dependencies
```bash
pip install -r requirements.txt