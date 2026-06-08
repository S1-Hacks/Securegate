cat > securegate/finding_schema.py << 'EOF'
from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    id: str                        # CVE ID or Semgrep rule ID
    title: str                     # Human-readable name
    severity: str                  # CRITICAL / HIGH / MEDIUM / LOW
    source: str                    # "SAST" or "SCA"
    file_path: Optional[str]       # SAST: path to file
    line_number: Optional[int]     # SAST: line number
    package: Optional[str]         # SCA: package name
    installed_version: Optional[str]
    fixed_version: Optional[str]
    description: str
    reachable: Optional[bool]      # None=unknown, True=reachable, False=suppressed
    cve_url: Optional[str]
EOF