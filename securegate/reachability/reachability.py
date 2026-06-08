"""
reachability.py — decide which SCA (dependency) findings are actually reachable.

`apply_reachability(findings, source_dir)` sets `finding.reachable` on every finding:

    reachable = True   -> keep it (real risk, or we can't prove it's safe)
    reachable = False  -> suppress it as noise (proven not called)

Decision rules
--------------
1. SAST findings           -> always reachable=True. They are flaws in *our own* code
                              that already exist on a real line; never filter them.
2. SCA finding, unknown    -> reachable=True. If the CVE/package isn't in our function
   CVE/package                map we can't reason about it, so we keep it (no false negatives).
3. SCA finding, no call    -> reachable=True. If the call graph couldn't be built, we have
   graph available            no evidence and must stay conservative.
4. SCA finding, known +    -> reachable = (any vulnerable function appears in the call graph).
   graph available            If the dangerous function is never called -> False (suppressed).

Note on coupling: we import the real `Finding` only for type checking and otherwise use
duck typing (read `.source`/`.id`/`.package`, set `.reachable`). This keeps the module
importable even while the shared schema file is being finalised, and avoids hard coupling.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Sequence

from securegate.reachability.callgraph_builder import CallGraph, build_call_graph
from securegate.reachability.cve_function_map import (
    get_ecosystem,
    get_functions_for_cve,
    get_functions_for_package,
    is_known,
)

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from securegate.finding_schema import Finding


def _vulnerable_functions(finding) -> List[str]:
    """All vulnerable function names for a finding, resolved by CVE id then package."""
    funcs = get_functions_for_cve(getattr(finding, "id", "") or "")
    if funcs:
        return funcs
    return get_functions_for_package(getattr(finding, "package", "") or "")


def _resolve_one(finding, graph: CallGraph) -> bool:
    """Compute the reachable flag for a single SCA finding (see module rules 2-4)."""
    cve_id = getattr(finding, "id", "") or ""
    package = getattr(finding, "package", "") or ""

    # Rule 2: we don't know this CVE/package -> keep it.
    if not is_known(cve_id, package):
        return True

    # Rule 3: no usable call graph -> keep it.
    if not graph.analyzed:
        return True

    # Rule 4: suppress only if none of the vulnerable functions are ever called.
    # Scope the check to the package's ecosystem so a JS call can't mark a pip dep
    # reachable (and vice-versa).
    funcs = _vulnerable_functions(finding)
    if not funcs:
        return True
    ecosystem = get_ecosystem(cve_id, package) or ""
    # maybe_calls() also catches dynamic dispatch (computed access / getattr) so we don't
    # silently suppress a vulnerable function that's invoked indirectly.
    return any(graph.maybe_calls(fn, ecosystem) for fn in funcs)


def apply_reachability(findings: Sequence["Finding"], source_dir: str) -> List["Finding"]:
    """Mark every finding's `.reachable` flag in place and return the same list.

    SAST findings are always reachable=True. SCA findings are resolved against the call
    graph built from `source_dir`. Safe on empty input and unanalysable source trees.
    """
    findings = list(findings or [])
    if not findings:
        return findings

    graph = build_call_graph(source_dir)

    for finding in findings:
        source = (getattr(finding, "source", "") or "").upper()
        if source == "SAST":
            finding.reachable = True
            continue
        # Treat anything that isn't SAST as a dependency (SCA) finding.
        finding.reachable = _resolve_one(finding, graph)

    return findings


def suppression_rate(findings: Sequence["Finding"]) -> float:
    """Fraction of SCA findings marked unreachable (reachable=False). 0.0 if none.

    Useful for the demo's "≥60% of raw SCA findings suppressed" validation.
    """
    sca = [f for f in findings if (getattr(f, "source", "") or "").upper() == "SCA"]
    if not sca:
        return 0.0
    suppressed = sum(1 for f in sca if getattr(f, "reachable", None) is False)
    return suppressed / len(sca)
