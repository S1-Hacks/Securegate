"""
cve_function_map.py — maps a CVE to the specific vulnerable function(s) it lives in.

Why this exists
---------------
A dependency vulnerability is only *exploitable* if your code actually invokes the
function that contains the flaw. Importing a vulnerable package but never calling its
dangerous function means the CVE is unreachable — pure noise that should be suppressed.

This map is the ground truth that the reachability engine checks the call graph against.
For the hackathon we hardcode the seeded demo CVEs; in production this would come from a
vulnerability-intelligence feed (e.g. GitHub Advisory affected-functions, or a custom DB).
"""

from typing import Dict, List, Optional

# CVE ID -> {package, ecosystem, vulnerable function names}
# `functions` are matched against *call sites* in the analysed source (method/function names).
CVE_FUNCTION_MAP: Dict[str, Dict[str, object]] = {
    "CVE-2021-23337": {
        "package": "lodash",
        "ecosystem": "npm",
        "functions": ["template"],
    },
    "CVE-2022-24999": {
        "package": "express",
        "ecosystem": "npm",
        "functions": ["send"],
    },
    "CVE-2021-34552": {
        "package": "Pillow",
        "ecosystem": "pip",
        "functions": ["frombytes", "crop"],
    },
    "CVE-2023-32681": {
        "package": "requests",
        "ecosystem": "pip",
        "functions": ["get", "post"],
    },
}


def _norm(name: str) -> str:
    """Normalise a package name for case-insensitive comparison (Pillow vs pillow)."""
    return (name or "").strip().lower()


# Reverse index: package name (normalised) -> set of vulnerable function names.
# Lets us resolve reachability even when the SCA finding's CVE id isn't in our map
# but its package is.
_PACKAGE_INDEX: Dict[str, List[str]] = {}
_PACKAGE_ECOSYSTEM: Dict[str, str] = {}  # normalised package -> "pip" | "npm"
for _entry in CVE_FUNCTION_MAP.values():
    _pkg = _norm(str(_entry["package"]))
    _PACKAGE_INDEX.setdefault(_pkg, [])
    _PACKAGE_ECOSYSTEM.setdefault(_pkg, str(_entry.get("ecosystem", "")))
    for _fn in _entry["functions"]:  # type: ignore[union-attr]
        if _fn not in _PACKAGE_INDEX[_pkg]:
            _PACKAGE_INDEX[_pkg].append(_fn)


def get_functions_for_cve(cve_id: str) -> List[str]:
    """Return the vulnerable function names for a CVE id, or [] if unknown."""
    entry = CVE_FUNCTION_MAP.get((cve_id or "").strip())
    if not entry:
        return []
    return list(entry["functions"])  # type: ignore[arg-type]


def get_functions_for_package(package: str) -> List[str]:
    """Return all known vulnerable function names for a package, or [] if unknown."""
    return list(_PACKAGE_INDEX.get(_norm(package), []))


def get_ecosystem(cve_id: str = "", package: str = "") -> Optional[str]:
    """Return the ecosystem ("pip"/"npm") for a CVE id or package, or None if unknown.

    Used to scope reachability checks to the right language's call sites.
    """
    entry = CVE_FUNCTION_MAP.get((cve_id or "").strip())
    if entry and entry.get("ecosystem"):
        return str(entry["ecosystem"])
    return _PACKAGE_ECOSYSTEM.get(_norm(package)) or None


def is_known(cve_id: str = "", package: str = "") -> bool:
    """True if we have a vulnerable-function mapping for this CVE id or package."""
    if cve_id and cve_id.strip() in CVE_FUNCTION_MAP:
        return True
    if package and _norm(package) in _PACKAGE_INDEX:
        return True
    return False
