"""
Unit tests for the SecureGate reachability engine (Dev 2).

Tests are hermetic: each builds its own tiny source tree in `tmp_path` instead of relying
on demo-repo or external call-graph tools. Finding objects are represented with a light
SimpleNamespace double, because the engine only duck-types a few attributes; one
integration test exercises the real `Finding` dataclass and skips if it isn't importable.
"""

from types import SimpleNamespace

import pytest

from securegate.reachability.callgraph_builder import build_call_graph
from securegate.reachability.cve_function_map import (
    get_functions_for_cve,
    get_functions_for_package,
    is_known,
)
from securegate.reachability.dedup import deduplicate
from securegate.reachability.reachability import apply_reachability, suppression_rate


def finding(**kw):
    """Build a finding-like object with the schema's fields (test double)."""
    defaults = dict(
        id="", title="", severity="HIGH", source="SCA",
        file_path=None, line_number=None, package=None,
        installed_version=None, fixed_version=None,
        description="", reachable=None, cve_url=None,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


# --------------------------------------------------------------------------- #
# callgraph_builder
# --------------------------------------------------------------------------- #
def test_python_calls_are_detected(tmp_path):
    (tmp_path / "m.py").write_text(
        "from PIL import Image\n"
        "def f(p):\n"
        "    img = Image.open(p)\n"
        "    return img.crop((0, 0, 1, 1))\n"
    )
    g = build_call_graph(str(tmp_path))
    assert g.analyzed
    assert g.calls("crop")
    assert g.calls("open")
    assert "PIL" in g.imported_modules


def test_js_calls_are_detected(tmp_path):
    (tmp_path / "a.js").write_text(
        "const _ = require('lodash');\n"
        "const t = _.template('<%= x %>');\n"
    )
    g = build_call_graph(str(tmp_path))
    assert g.analyzed
    assert g.calls("template")
    assert "lodash" in g.imported_modules


def test_corrupted_file_is_skipped_not_crashed(tmp_path):
    # Genuinely malformed Python (real SyntaxError) -> must be skipped, not crash.
    (tmp_path / "bad.py").write_text("def broken(:\n    pass\n")
    g = build_call_graph(str(tmp_path))
    assert g.files_failed == 1
    assert not g.analyzed  # nothing parsed -> caller stays conservative


def test_missing_dir_is_safe():
    g = build_call_graph("/no/such/dir/xyz")
    assert not g.analyzed
    assert g.called_functions == set()


# --------------------------------------------------------------------------- #
# cve_function_map
# --------------------------------------------------------------------------- #
def test_cve_lookup():
    assert get_functions_for_cve("CVE-2021-23337") == ["template"]
    assert set(get_functions_for_cve("CVE-2021-34552")) == {"frombytes", "crop"}
    assert get_functions_for_cve("CVE-0000-00000") == []


def test_package_lookup_is_case_insensitive():
    assert get_functions_for_package("pillow") == get_functions_for_package("Pillow")
    assert "crop" in get_functions_for_package("Pillow")
    assert is_known(package="requests")
    assert not is_known(cve_id="CVE-9999-9999", package="totally-unknown-pkg")


# --------------------------------------------------------------------------- #
# reachability — the two required cases + edge cases
# --------------------------------------------------------------------------- #
def test_finding_with_function_in_callgraph_is_reachable(tmp_path):
    (tmp_path / "app.js").write_text("const _=require('lodash'); _.template('x');\n")
    f = finding(id="CVE-2021-23337", package="lodash", source="SCA")
    apply_reachability([f], str(tmp_path))
    assert f.reachable is True


def test_finding_with_function_not_in_callgraph_is_unreachable(tmp_path):
    # lodash imported but template() never called -> unreachable
    (tmp_path / "app.js").write_text("const _=require('lodash'); _.sortBy([], 'n');\n")
    f = finding(id="CVE-2021-23337", package="lodash", source="SCA")
    apply_reachability([f], str(tmp_path))
    assert f.reachable is False


def test_dynamic_dispatch_is_treated_as_reachable(tmp_path):
    # Vulnerable fn invoked indirectly via computed member access -> must NOT be suppressed.
    (tmp_path / "app.js").write_text("const _=require('lodash'); const f=_['template']; f('x');\n")
    f = finding(id="CVE-2021-23337", package="lodash", source="SCA")
    apply_reachability([f], str(tmp_path))
    assert f.reachable is True


def test_python_getattr_dispatch_is_reachable(tmp_path):
    (tmp_path / "app.py").write_text(
        "from PIL import Image\n"
        "def f(p):\n    fn = getattr(Image.open(p), 'crop')\n    return fn((0,0,1,1))\n"
    )
    f = finding(id="CVE-2021-34552", package="Pillow", source="SCA")
    apply_reachability([f], str(tmp_path))
    assert f.reachable is True


def test_sast_findings_are_never_suppressed(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")  # nothing relevant called
    f = finding(id="python.lang.security.audit", source="SAST", package=None)
    apply_reachability([f], str(tmp_path))
    assert f.reachable is True


def test_unknown_cve_is_kept_conservatively(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    f = finding(id="CVE-2099-12345", package="some-unmapped-pkg", source="SCA")
    apply_reachability([f], str(tmp_path))
    assert f.reachable is True


def test_no_callgraph_keeps_findings(tmp_path):
    # empty dir => graph not analyzed => conservative keep
    f = finding(id="CVE-2021-23337", package="lodash", source="SCA")
    apply_reachability([f], str(tmp_path))
    assert f.reachable is True


def test_demo_like_repo_suppresses_at_least_60_percent(tmp_path):
    # Recreate the demo's intent: vulnerable functions are imported but never called.
    (tmp_path / "app.py").write_text(
        "import requests\nfrom PIL import Image\n"
        "def r(p):\n    return Image.open(p).resize((8, 6))\n"
    )
    (tmp_path / "app.js").write_text(
        "const _=require('lodash');const e=require('express');\n"
        "_.sortBy([], 'n');\n"
    )
    findings = [
        finding(id="CVE-2021-23337", package="lodash", source="SCA"),    # template not called
        finding(id="CVE-2022-24999", package="express", source="SCA"),   # send not called
        finding(id="CVE-2021-34552", package="Pillow", source="SCA"),    # crop/frombytes not called
        finding(id="CVE-2023-32681", package="requests", source="SCA"),  # get/post not called
    ]
    apply_reachability(findings, str(tmp_path))
    rate = suppression_rate(findings)
    assert rate >= 0.60, f"only {rate:.0%} suppressed"


# --------------------------------------------------------------------------- #
# dedup
# --------------------------------------------------------------------------- #
def test_same_cve_from_sast_and_sca_surfaced_once():
    sca = finding(id="CVE-2021-23337", source="SCA", package="lodash", reachable=False)
    sast = finding(id="CVE-2021-23337", source="SAST", file_path="a.js", line_number=10)
    out = deduplicate([sast, sca])
    assert len(out) == 1
    kept = out[0]
    assert kept.source == "SCA"          # richer record wins
    assert kept.reachable is True        # SAST twin proves reachability


def test_exact_duplicates_removed():
    a = finding(id="CVE-2023-32681", source="SCA", package="requests")
    b = finding(id="CVE-2023-32681", source="SCA", package="requests")
    assert len(deduplicate([a, b])) == 1


def test_non_cve_findings_not_collapsed():
    a = finding(id="python.lang.audit", source="SAST", file_path="x.py", line_number=1)
    b = finding(id="python.lang.audit", source="SAST", file_path="y.py", line_number=2)
    assert len(deduplicate([a, b])) == 2  # different locations -> both kept


def test_empty_inputs_are_safe():
    assert deduplicate([]) == []
    assert apply_reachability([], "/tmp") == []
    assert suppression_rate([]) == 0.0


# --------------------------------------------------------------------------- #
# integration with the real Finding dataclass (skips if shared file is corrupted)
# --------------------------------------------------------------------------- #
def test_with_real_finding_schema_if_available(tmp_path):
    try:
        from securegate.finding_schema import Finding
    except Exception:
        pytest.skip("finding_schema.py not importable yet (shared file pending fix)")
    (tmp_path / "app.js").write_text("const _=require('lodash'); _.sortBy([], 'n');\n")
    f = Finding(
        id="CVE-2021-23337", title="lodash template injection", severity="HIGH",
        source="SCA", file_path=None, line_number=None, package="lodash",
        installed_version="4.17.15", fixed_version="4.17.21",
        description="prototype pollution", reachable=None,
        cve_url="https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
    )
    apply_reachability([f], str(tmp_path))
    assert f.reachable is False  # template() never called
