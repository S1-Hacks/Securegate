# SecureGate

> **CI-native security scanning with reachability-filtered merge gating.**
> Drop one workflow file into any repo — SecureGate scans every PR for vulnerabilities, filters out the noise, posts a findings report as a PR comment, and blocks the merge until issues are resolved.

---

## The problem

Modern security tools produce too much noise. A typical Node or Python project can surface 50+ CVEs on every scan — most of them in dependency code that your application never actually calls. Developers learn to ignore the alerts. Real vulnerabilities slip through.

## How SecureGate fixes it

SecureGate combines three layers:

1. **SAST (Semgrep)** — scans your source code for code-level flaws: SQL injection, command injection, hardcoded secrets, XSS, and more.
2. **SCA (Grype)** — scans your dependency manifests (`package.json`, `requirements.txt`) against the NVD and GitHub Advisory databases for known CVEs.
3. **Reachability analysis** — builds a call graph of your actual code and suppresses any SCA finding whose vulnerable function is never called. A CVE in `lodash.template()` doesn't matter if you never call `template()`.

The result: instead of 50 findings, you see 6 — the ones that are actually exploitable in your codebase.

---

## Demo

| Before fix | After fix |
|---|---|
| ![blocked](https://img.shields.io/badge/merge-blocked-red) | ![passing](https://img.shields.io/badge/merge-passing-green) |
| CRITICAL/HIGH findings in PR comment | ✅ No blocking findings |
| Red nodes in call graph | Green suppressed nodes |
| Merge button greyed out | Merge button active |

**Demo narrative:**
1. Open a PR with vulnerable code → pipeline triggers automatically
2. Bot posts a findings report directly on the PR
3. Call graph shows which vulnerable functions are reachable vs suppressed
4. Merge is blocked by the gate
5. Fix the vulnerabilities → push → pipeline re-runs → comment updates → merge unblocked

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Pull Request                       │
└──────────────────────────┬──────────────────────────────────┘
                           │ triggers
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
    ┌──────────┐    ┌──────────┐    ┌──────────────┐
    │   SAST   │    │   SCA    │    │  Orchestrate │
    │ Semgrep  │    │  Grype   │    │   & Gate     │
    └────┬─────┘    └────┬─────┘    └──────┬───────┘
         │               │                 │
         ▼               ▼                 │
    list[Finding]   list[Finding]          │
         │               │                 │
         └───────┬────────┘                │
                 ▼                         │
        ┌─────────────────┐                │
        │  Reachability   │                │
        │    Engine       │                │
        │  (call graph)   │                │
        └────────┬────────┘                │
                 │                         │
         reachable=True/False              │
                 │                         │
                 └─────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼                         ▼
       ┌─────────────┐         ┌──────────────┐
       │  PR Comment │         │  Merge Gate  │
       │    (bot)    │         │ (commit status│
       └─────────────┘         └──────────────┘
```

### Component breakdown

| Component | File | What it does |
|-----------|------|-------------|
| SAST parser | `securegate/parsers/semgrep_parser.py` | Maps Semgrep JSON → `list[Finding]`. All SAST findings are always `reachable=True`. |
| SCA parser | `securegate/parsers/grype_parser.py` | Maps Grype JSON → `list[Finding]`. Prefers CVE IDs over GHSA. `reachable=None` until engine decides. |
| Call graph builder | `securegate/reachability/callgraph_builder.py` | Walks source files using Python AST + JS regex. Extracts every function/method call site. Scoped per ecosystem (pip vs npm). |
| CVE function map | `securegate/reachability/cve_function_map.py` | Maps CVE ID → vulnerable function name(s). Used to check if a CVE's dangerous function is ever called. |
| Reachability engine | `securegate/reachability/reachability.py` | Marks each SCA finding `reachable=True/False`. SAST always `True`. Unknown CVEs stay `True` (no false negatives). |
| PR bot | `securegate/bot/bot.py` | Posts/updates the findings comment on the PR via PyGithub. Uses a comment tag to avoid duplicates on re-scan. |
| Formatter | `securegate/bot/formatter.py` | Renders the Markdown comment: severity table, suppressed section, and a Mermaid call graph diagram. |
| Merge gate | `securegate/orchestrator/merge_gate.py` | Sets GitHub commit status (pass/fail) based on policy. Supports `security-override` label bypass. |
| Orchestrator | `securegate/orchestrator/orchestrator.py` | Wires everything together. Reads scan artifacts, calls each component in sequence, exits 1 to block the merge. |

### The `Finding` schema

Every component produces or consumes `Finding` objects:

```python
@dataclass
class Finding:
    id: str                    # CVE ID or Semgrep rule ID
    title: str                 # Human-readable name
    severity: str              # CRITICAL / HIGH / MEDIUM / LOW
    source: str                # "SAST" or "SCA"
    file_path: Optional[str]   # SAST: path to file
    line_number: Optional[int] # SAST: line number
    package: Optional[str]     # SCA: package name
    installed_version: Optional[str]
    fixed_version: Optional[str]
    description: str
    reachable: Optional[bool]  # None=unknown, True=reachable, False=suppressed
    cve_url: Optional[str]
```

---

## Reachability analysis — how it works

This is SecureGate's key differentiator. Here's the decision logic for each SCA finding:

| Condition | Result |
|-----------|--------|
| Finding is SAST | Always `reachable=True` — code flaws are never filtered |
| CVE/package not in our function map | `reachable=True` — unknown risk, keep it (no false negatives) |
| Call graph could not be built | `reachable=True` — no evidence, stay conservative |
| Vulnerable function IS in the call graph | `reachable=True` — actively exploitable |
| Vulnerable function NOT in call graph | `reachable=False` — suppressed as noise |

### Seeded CVE function map

| CVE | Package | Vulnerable function(s) |
|-----|---------|----------------------|
| CVE-2021-23337 | lodash | `template()` |
| CVE-2022-24999 | express | `send()` |
| CVE-2021-34552 | Pillow | `frombytes()`, `crop()` |
| CVE-2023-32681 | requests | `get()`, `post()` |

---

## Policy configuration

Drop a `.securegate.yml` file in your repo root to customise the gate:

```yaml
# Block the merge on these severity levels
block_on_critical: true
block_on_high: true
block_on_medium: false

# Permanently suppress specific CVEs (accepted risk)
suppress:
  - CVE-2021-23337

# PR label that bypasses the gate entirely
override_label: "security-override"
```

If no `.securegate.yml` is present, SecureGate defaults to blocking on CRITICAL and HIGH.

---

## Using SecureGate on any repo

Copy `examples/securegate.yml` into your repo's `.github/workflows/` directory:

```bash
mkdir -p .github/workflows
curl -o .github/workflows/securegate.yml \
  https://raw.githubusercontent.com/S1-Hacks/Securegate/main/examples/securegate.yml
git add .github/workflows/securegate.yml
git commit -m "add SecureGate security scanning"
git push
```

Then open a pull request — SecureGate fires automatically.

### Optional: Semgrep authenticated rulesets

For full OWASP Top 10 + secrets detection coverage, add a `SEMGREP_APP_TOKEN` secret to your repo:

1. Sign up free at [semgrep.dev](https://semgrep.dev)
2. Go to **Settings → Tokens** → create a token
3. Add it to your repo: **Settings → Secrets → Actions → New secret**
   - Name: `SEMGREP_APP_TOKEN`
   - Value: your token

Without the token, SecureGate falls back to `--config auto` (community rules, still useful).

### Required GitHub permissions

The workflow declares these permissions automatically:

```yaml
permissions:
  pull-requests: write  # post PR comments
  statuses: write       # set commit status (merge gate)
  contents: read        # checkout code
```

### Branch protection (to enforce the gate)

For the merge gate to physically disable the merge button:

1. Go to **Settings → Branches → Add rule**
2. Branch name pattern: `main`
3. Enable **Require status checks to pass before merging**
4. Search for and add: `Orchestrate & Gate`
5. Save

---

## Local development

```bash
# Clone and set up
git clone https://github.com/S1-Hacks/Securegate.git
cd Securegate
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Run scanners against demo-repo
semgrep --config auto --json demo-repo/src/ > sast-results.json 2>/dev/null
grype dir:demo-repo --output json > sca-results.json 2>/dev/null

# Run the full pipeline locally
COMMIT_SHA=local python3 -m securegate.orchestrator.orchestrator
```

### Run tests

```bash
python -m pytest tests/ -v
```

---

## Project structure

```
Securegate/
├── .github/
│   └── workflows/
│       └── securegate.yml       # Internal CI — scans this repo's own PRs
├── examples/
│   └── securegate.yml           # Drop this into any repo to enable SecureGate
├── securegate/
│   ├── finding_schema.py        # Shared Finding dataclass — the data contract
│   ├── parsers/
│   │   ├── semgrep_parser.py    # Semgrep JSON → list[Finding]
│   │   └── grype_parser.py      # Grype JSON → list[Finding]
│   ├── reachability/
│   │   ├── callgraph_builder.py # AST + regex call graph extraction
│   │   ├── reachability.py      # apply_reachability() — marks findings reachable/suppressed
│   │   ├── cve_function_map.py  # CVE ID → vulnerable function name mapping
│   │   └── dedup.py             # Deduplicates findings appearing in both SAST + SCA
│   ├── bot/
│   │   ├── formatter.py         # Renders Markdown comment + Mermaid call graph
│   │   └── bot.py               # Posts/updates PR comment via PyGithub
│   └── orchestrator/
│       ├── orchestrator.py      # Main entrypoint — wires all components together
│       └── merge_gate.py        # Sets GitHub commit status based on policy
├── demo-repo/                   # Seeded vulnerable app for demo scanning
│   ├── src/
│   │   ├── app.js               # Node/Express with SQL injection, hardcoded secrets, eval()
│   │   └── app.py               # Python with os.system() injection, SQL injection
│   ├── package.json             # Vulnerable: lodash 4.17.15, express 4.17.1
│   └── requirements.txt         # Vulnerable: Pillow 8.2.0, requests 2.25.0, jinja2 2.11.2
├── tests/
│   └── test_reachability.py     # Reachability engine unit tests
├── .securegate.yml              # Policy config for this repo
└── requirements.txt             # Python dependencies
```

---

## Built with

| Tool | Role |
|------|------|
| [Semgrep](https://semgrep.dev) | SAST — static code analysis |
| [Grype](https://github.com/anchore/grype) | SCA — dependency CVE scanning |
| [PyGithub](https://pygithub.readthedocs.io) | GitHub API — PR comments + commit status |
| [pycg](https://github.com/vitsalis/PyCG) | Python call graph backend |
| Python AST | Built-in Python call graph extraction |
| Mermaid | Call graph visualization in PR comments |

---

## Team

Built in one day as a hackathon sprint at SentinelOne.

| Dev | Owned |
|-----|-------|
| Dev 1 | CI/CD workflow, Semgrep + Grype parsers, orchestrator |
| Dev 2 | Call graph builder, reachability engine, CVE function map |
| Dev 3 | PR bot, formatter, merge gate, policy config |
