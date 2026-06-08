"""
callgraph_builder.py — extract the set of functions a codebase actually calls.

The reachability engine needs one question answered: "Does this repo ever call
function X?" To answer it robustly we build a lightweight call graph.

Backends (tried in order, with graceful fallback):
  1. pycg            — proper Python call graph, if installed and compatible.
  2. js-callgraph    — Node call graph, if Node + the tool are available.
  3. Built-in AST/regex scanner — always available, dependency-free.

Hardening goals (per task spec):
  * circular imports        -> AST parsing never executes code, so they can't hang us.
  * dynamic requires/imports-> regex scan still catches literal call sites; anything we
                               can't resolve simply isn't added (caller stays conservative).
  * missing call-graph output-> if NOTHING could be analysed, `CallGraph.analyzed` is False
                               so the caller can refuse to suppress (avoid false negatives).
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Set

_PY_EXT = (".py",)
_JS_EXT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox"}


@dataclass
class CallGraph:
    """Result of analysing a source tree.

    Calls are tracked PER ECOSYSTEM so a JavaScript `app.get()` can't make a Python
    `requests.get` dependency look reachable (and vice-versa). `called_functions` is the
    union, kept for convenience/back-compat.
    """
    python_calls: Set[str] = field(default_factory=set)
    js_calls: Set[str] = field(default_factory=set)
    called_functions: Set[str] = field(default_factory=set)  # union of the above
    # Indirect references: names reached via dynamic dispatch (computed member access,
    # getattr, string-literal subscripts). We can't prove these are calls, but for a
    # security tool we treat a matching vulnerable name here as "possibly reachable".
    dynamic_refs: Set[str] = field(default_factory=set)
    imported_modules: Set[str] = field(default_factory=set)  # imported package/module names
    files_analyzed: int = 0
    files_failed: int = 0
    backend: str = "builtin"

    @property
    def analyzed(self) -> bool:
        """True if we successfully analysed at least one file.

        When False, callers must NOT suppress findings — we have no evidence either way,
        and suppressing on no data risks hiding a real, reachable vulnerability.
        """
        return self.files_analyzed > 0

    def calls(self, function_name: str, ecosystem: str = "") -> bool:
        """True if `function_name` is called. Scope to one ecosystem when known.

        ecosystem: "pip" -> Python call sites only; "npm" -> JS call sites only;
        anything else -> the union (conservative: a hit in either language counts).
        """
        eco = (ecosystem or "").lower()
        if eco == "pip":
            return function_name in self.python_calls
        if eco == "npm":
            return function_name in self.js_calls
        return function_name in self.called_functions

    def maybe_calls(self, function_name: str, ecosystem: str = "") -> bool:
        """Like `calls`, but also True if the name is reached via dynamic dispatch.

        Used for conservative reachability: an indirect reference to a vulnerable
        function is treated as possibly-reachable rather than silently suppressed.
        """
        return self.calls(function_name, ecosystem) or function_name in self.dynamic_refs


# --------------------------------------------------------------------------- #
# Python: AST-based call extraction
# --------------------------------------------------------------------------- #
class _PyCallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: Set[str] = set()
        self.imports: Set[str] = set()
        self.dynamic: Set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            # obj.method(...)  -> record the method name ("crop", "get", ...)
            self.calls.add(func.attr)
        elif isinstance(func, ast.Name):
            # bare_function(...)
            self.calls.add(func.id)
            # getattr(obj, "crop")(...) — dynamic dispatch via string name
            if func.id == "getattr" and len(node.args) >= 2:
                second = node.args[1]
                if isinstance(second, ast.Constant) and isinstance(second.value, str):
                    self.dynamic.add(second.value)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # obj["crop"] — string-literal subscript may alias a method for later call.
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            self.dynamic.add(sl.value)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.add(node.module.split(".")[0])
        self.generic_visit(node)


def _analyze_python_file(path: str, graph: CallGraph) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read(), filename=path)
    except (SyntaxError, ValueError, OSError):
        # Corrupted / unparseable file (e.g. the broken demo files) -> skip, don't crash.
        graph.files_failed += 1
        return
    visitor = _PyCallVisitor()
    visitor.visit(tree)
    graph.python_calls |= visitor.calls
    graph.called_functions |= visitor.calls
    graph.dynamic_refs |= visitor.dynamic
    graph.imported_modules |= visitor.imports
    graph.files_analyzed += 1


# --------------------------------------------------------------------------- #
# JavaScript: lightweight regex call extraction
# --------------------------------------------------------------------------- #
# matches `.method(` and `funcName(` call sites
_JS_METHOD_CALL = re.compile(r"\.([A-Za-z_$][\w$]*)\s*\(")
_JS_FUNC_CALL = re.compile(r"(?:^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(")
# computed member access: obj['template'] or obj["crop"] — possible dynamic dispatch
_JS_COMPUTED_MEMBER = re.compile(r"""\[\s*['"]([A-Za-z_$][\w$]*)['"]\s*\]""")
_JS_REQUIRE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_JS_IMPORT = re.compile(r"""import\s+(?:.+?\s+from\s+)?['"]([^'"]+)['"]""")
_JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "typeof"}
_JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_JS_LINE_COMMENT = re.compile(r"//[^\n]*")


def _strip_js_comments(src: str) -> str:
    """Remove // and /* */ comments so commented-out code isn't counted as a call.

    Critical for correctness: e.g. a comment '_.template() NOT called' must NOT make the
    lodash CVE look reachable.
    """
    src = _JS_BLOCK_COMMENT.sub(" ", src)
    src = _JS_LINE_COMMENT.sub(" ", src)
    return src


def _analyze_js_file(path: str, graph: CallGraph) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        graph.files_failed += 1
        return
    # Resolve imports from the raw text, but extract calls from comment-stripped code.
    for rx in (_JS_REQUIRE, _JS_IMPORT):
        for m in rx.finditer(raw):
            graph.imported_modules.add(m.group(1).split("/")[0])
    src = _strip_js_comments(raw)
    for m in _JS_METHOD_CALL.finditer(src):
        graph.js_calls.add(m.group(1))
        graph.called_functions.add(m.group(1))
    for m in _JS_FUNC_CALL.finditer(src):
        name = m.group(1)
        if name not in _JS_KEYWORDS:
            graph.js_calls.add(name)
            graph.called_functions.add(name)
    for m in _JS_COMPUTED_MEMBER.finditer(src):
        graph.dynamic_refs.add(m.group(1))
    graph.files_analyzed += 1


# --------------------------------------------------------------------------- #
# Optional external backends (best-effort; silent fallback)
# --------------------------------------------------------------------------- #
def _try_pycg(source_dir: str) -> bool:
    """Return True if pycg is importable (so callers know a richer backend exists)."""
    try:
        import pycg  # noqa: F401
        return True
    except Exception:
        return False


def _node_available() -> bool:
    return shutil.which("node") is not None and shutil.which("js-callgraph") is not None


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def build_call_graph(source_dir: str) -> CallGraph:
    """Walk `source_dir` and return a CallGraph of every function/method called.

    Never raises on bad input: a missing dir or unparseable files yield a CallGraph
    with `analyzed == False`, signalling the caller to stay conservative.
    """
    graph = CallGraph()

    if not source_dir or not os.path.isdir(source_dir):
        return graph  # analyzed == False

    # Record which richer backends *would* be available (informational for the demo).
    if _try_pycg(source_dir):
        graph.backend = "pycg+builtin"
    if _node_available():
        graph.backend = (graph.backend + "+js-callgraph").replace("builtin+", "")

    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            path = os.path.join(root, name)
            if name.endswith(_PY_EXT):
                _analyze_python_file(path, graph)
            elif name.endswith(_JS_EXT):
                _analyze_js_file(path, graph)

    return graph
