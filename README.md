## Branch Ownership

| Branch | Owner | Responsibility |
|--------|-------|----------------|
| `feature/scanning-pipeline` | Dev 1 | CI/CD, Semgrep, Grype, parsers |
| `feature/reachability-engine` | Dev 2 | Call graph, reachability filter, dedup |
| `feature/pr-bot-and-gates` | Dev 3 | PR bot, merge gate, policy config |

## Setup

```bash
pip install -r requirements.txt
```

## Project Structure
```
securegate/ ├── finding_schema.py # Shared data contract — read before coding ├── parsers/ # Dev 1 ├── reachability/ # Dev 2 ├── bot/ # Dev 3 ├── orchestrator/ # Dev 1 + Dev 2 (Day 2 integration) demo-repo/ # Seeded vuln app for scanning .github/workflows/ # Dev 1 .securegate.yml # Policy config — Dev 3
```

Testing demo