"""
The two structural promises, asserted against the source rather than the README.

*Vigil never touches the network* and *the engine is pure standard library* are
claims a reader cannot check by running the tool — a scanner that phoned home
would look identical from the outside. So both are read straight out of the
import graph, which is the only place they can be true or false.
"""

import ast
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "vigil")

# Anything that could open a connection, resolve a name, or run something that
# would. None of these may appear anywhere in the package.
NETWORK_MODULES = {
    "socket", "ssl", "asyncio", "selectors", "requests", "httpx", "urllib3",
    "urllib.request", "urllib.error", "http", "http.client", "ftplib",
    "smtplib", "imaplib", "poplib", "telnetlib", "xmlrpc", "webbrowser",
    "subprocess", "multiprocessing", "socketserver", "wsgiref", "aiohttp",
    "paramiko", "boto3", "dns", "pycurl",
}

# What the engine is allowed to stand on: the standard library, and itself.
ENGINE_ALLOWED = {
    "re", "math", "json", "os", "sys", "enum", "typing", "dataclasses",
    "collections", "bisect", "itertools", "functools", "string",
    "__future__",
}


def _modules(directory: str) -> list[str]:
    found = []
    for base, _dirs, files in os.walk(directory):
        if "__pycache__" in base:
            continue
        for name in sorted(files):
            if name.endswith(".py"):
                found.append(os.path.join(base, name))
    return found


def _imports(path: str) -> set[str]:
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:                 # a relative import: our own package
                continue
            if node.module:
                names.add(node.module)
    return names


def _rel(path: str) -> str:
    return os.path.relpath(path, ROOT)


ALL_MODULES = _modules(PKG)
ENGINE_MODULES = _modules(os.path.join(PKG, "core"))


def test_the_package_has_modules_to_check():
    # Guard the guard: an empty walk would make every test below vacuous.
    assert len(ALL_MODULES) >= 10
    assert len(ENGINE_MODULES) >= 5


@pytest.mark.parametrize("path", ALL_MODULES, ids=_rel)
def test_nothing_in_the_package_can_reach_the_network(path):
    for name in _imports(path):
        root = name.split(".")[0]
        assert name not in NETWORK_MODULES, f"{_rel(path)} imports {name}"
        assert root not in NETWORK_MODULES, f"{_rel(path)} imports {name}"


@pytest.mark.parametrize("path", ENGINE_MODULES, ids=_rel)
def test_the_engine_stands_only_on_the_standard_library(path):
    for name in _imports(path):
        root = name.split(".")[0]
        assert root in ENGINE_ALLOWED, f"{_rel(path)} imports {name}"


@pytest.mark.parametrize("path", ENGINE_MODULES, ids=_rel)
def test_the_engine_never_imports_qt(path):
    for name in _imports(path):
        assert not name.startswith("PyQt"), _rel(path)
        assert not name.startswith("PySide"), _rel(path)


def test_the_command_line_never_imports_qt():
    for name in _imports(os.path.join(PKG, "cli.py")):
        assert not name.startswith("PyQt"), "the CLI must run without Qt"


def test_importing_the_cli_does_not_pull_in_qt():
    import subprocess
    import sys
    code = ("import sys; import vigil.cli; "
            "print(any(m.startswith('PyQt') for m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "False"


@pytest.mark.parametrize("path", ALL_MODULES, ids=_rel)
def test_every_module_opts_into_modern_annotations(path):
    if os.path.basename(path) == "__init__.py":
        return
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    assert "from __future__ import annotations" in source, _rel(path)


@pytest.mark.parametrize("path", ALL_MODULES, ids=_rel)
def test_every_module_explains_itself(path):
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    doc = ast.get_docstring(tree)
    if os.path.basename(path) == "__init__.py" and os.path.getsize(path) == 0:
        return
    assert doc and len(doc) > 40, _rel(path)
