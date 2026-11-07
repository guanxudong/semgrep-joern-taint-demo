"""Structural validation of every target's ground_truth.json against its source.

No-LLM, no-engine checks: every entrypoint file/function must exist, the route
(or non-HTTP trigger) must be registered as claimed, category-A sinks and
chains must resolve, the cwe/vuln_type mapping must match the shared taxonomy,
and GROUND_TRUTH.md must list exactly the JSON ids.

Run:
    uv run --with pytest pytest tests/test_ground_truth.py -q
"""

import ast
import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TARGETS_DIR = REPO / "targets"

A_TYPES = {"sqli", "xss", "cmdi", "path-traversal", "rce", "xxe",
           "deserialization", "ssti"}
B_TYPES = {"idor", "business-logic", "race-condition", "priv-esc",
           "mass-assignment", "broken-access-control", "auth-flaws"}
ALL_TYPES = A_TYPES | B_TYPES

CWE = {"sqli": 89, "xss": 79, "cmdi": 78, "path-traversal": 22, "rce": 94,
       "xxe": 611, "deserialization": 502, "ssti": 1336, "idor": 639,
       "business-logic": 840, "race-condition": 367, "priv-esc": 269,
       "mass-assignment": 915, "broken-access-control": 862,
       "auth-flaws": 287}

TARGETS = {
    "python-flask": {"prefix": "py-", "kind": "flask"},
    "js-ts-express": {"prefix": "js-", "kind": "express"},
    "java-spring": {"prefix": "java-", "kind": "spring"},
    "perl-cgi": {"prefix": "pl-", "kind": "cgi"},
    "java-fix-gateway": {"prefix": "jtg-", "kind": "registry-cmd"},
    "python-clearing-worker": {"prefix": "pycl-", "kind": "bus"},
}

_PARAM_RE = re.compile(r"<[^>]+>|\{[^}]+\}")
_VERB_PREFIXES = ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ")
_TRIGGER_PREFIXES = ("MSG ", "CMD ", "FILE ")


def _norm_path(p):
    return _PARAM_RE.sub("<>", p).rstrip("/") or "/"


def _read(path):
    return path.read_text(encoding="utf-8")


def _py_functions(path):
    tree = ast.parse(_read(path))
    return {n.name for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _java_functions(path):
    src = _read(path)
    pats = [
        r"(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\],.?\s]+?\s+(\w+)\s*\(",
        r"^\s*(?:static\s+)?[\w<>\[\],.?\s]+?\s+(\w+)\s*\([^;{}]*\)\s*(?:throws [\w, ]+)?\{",
    ]
    out = set()
    for p in pats:
        out |= set(re.findall(p, src, re.M))
    return out


def _js_functions(path):
    src = _read(path)
    pats = [
        r"function\s+(\w+)\s*\(",
        r"(?:const|let|var)\s+(\w+)\s*=",
        r"^\s*(\w+)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*(?::[^{=]+)?\{",
        r"(\w+)\s*[:=]\s*(?:async\s*)?(?:function|\()",
        r"exports\.(\w+)",
        r"export\s+(?:async\s+)?function\s+(\w+)",
        r"export\s+(?:const|let|var)\s+(\w+)",
    ]
    out = set()
    for p in pats:
        out |= set(re.findall(p, src, re.M))
    return out


def _perl_functions(path):
    return set(re.findall(r"^\s*sub\s+(\w+)", _read(path), re.M))


def _functions(path):
    suffix = path.suffix
    if suffix == ".py":
        return _py_functions(path)
    if suffix == ".java":
        return _java_functions(path)
    if suffix in (".js", ".ts"):
        return _js_functions(path)
    if suffix in (".pl", ".pm"):
        return _perl_functions(path)
    raise AssertionError(f"unknown suffix {suffix}")


def _flask_routes(root, entry_file):
    """Return {(normalized_path, verb)} declared in a Flask routes file."""
    tree = ast.parse(_read(root / entry_file))
    prefix = ""
    for node in tree.body:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "Blueprint"):
            for kw in node.value.keywords:
                if (kw.arg == "url_prefix" and isinstance(kw.value, ast.Constant)):
                    prefix = kw.value.value
    out = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "route" and dec.args
                    and isinstance(dec.args[0], ast.Constant)):
                p = _norm_path(prefix + dec.args[0].value)
                verbs = {"GET"}
                for kw in dec.keywords:
                    if (kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple))):
                        verbs = {elt.value for elt in kw.value.elts
                                 if isinstance(elt, ast.Constant)}
                for v in verbs:
                    out.add((p, v))
    return out


def _express_mounts(root):
    app = _read(root / "app.js")
    mounts = {}
    for var, name in re.findall(r"const\s+(\w+)\s*=\s*require\('\./routes/(\w+)'\)", app):
        m = re.search(rf"app\.use\('(/[^']*)',\s*{var}\)", app)
        if m:
            mounts[f"routes/{name}"] = m.group(1)
    return mounts


def _express_routes(root, entry_file):
    src = _read(root / entry_file)
    # resolve mount by matching the routes file stem against app.js requires
    stem = Path(entry_file).with_suffix("").as_posix()
    base = _express_mounts(root).get(stem, "")
    out = set()
    for verb, p in re.findall(
            r"router\.(get|post|put|delete|patch)\(\s*'([^']+)'", src):
        out.add((_norm_path(base + p), verb.upper()))
    return out


def _spring_routes(root, entry_file):
    src = _read(root / entry_file)
    cls = re.search(r'@RequestMapping\("([^"]*)"\)', src)
    prefix = cls.group(1) if cls else ""
    ann = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
           "DeleteMapping": "DELETE", "PatchMapping": "PATCH"}
    out = set()
    for name, p in re.findall(r'@(Get|Post|Put|Delete|Patch)Mapping\("([^"]*)"\)', src):
        out.add((_norm_path(prefix + p), name.upper()))
    return out


def _check_entry(root, kind, prefix, entry, errors):
    eid = entry["id"]
    if not eid.startswith(prefix):
        errors.append(f"{eid}: id prefix != {prefix}")
    vt = entry.get("vuln_type")
    if vt not in ALL_TYPES:
        errors.append(f"{eid}: unknown vuln_type {vt!r}")
    elif ((entry.get("category") == "A") != (vt in A_TYPES)):
        errors.append(f"{eid}: category {entry.get('category')} vs type {vt}")
    if entry.get("cwe") != CWE.get(vt):
        errors.append(f"{eid}: cwe {entry.get('cwe')} != {CWE.get(vt)} for {vt}")
    if ("-safe-" in eid) != (entry.get("expected") == "safe"):
        errors.append(f"{eid}: expected {entry.get('expected')} vs safe id")
    if entry.get("expected") == "vulnerable" and entry.get("difficulty") not in (
            "shallow", "medium", "deep"):
        errors.append(f"{eid}: bad difficulty {entry.get('difficulty')!r}")

    ep = entry.get("entrypoint", {})
    efile = ep.get("file")
    fpath = root / efile if efile else None
    if not efile or not fpath.is_file():
        errors.append(f"{eid}: entrypoint file missing: {efile}")
        return
    fn = ep.get("function")
    route = ep.get("route", "")

    if kind == "express":
        # Express handlers are anonymous; verify the verb+path registration.
        want_verb = route.split(" ", 1)[0].upper()
        want_path = _norm_path(route.split(" ", 1)[1])
        if (want_path, want_verb) not in _express_routes(root, efile):
            errors.append(f"{eid}: route {route} not registered in {efile}")
    else:
        funcs = _functions(fpath)
        if fn not in funcs:
            errors.append(f"{eid}: function {fn!r} not found in {efile}")
        if kind == "flask":
            want_verb = route.split(" ", 1)[0].upper()
            want_path = _norm_path(route.split(" ", 1)[1])
            if (want_path, want_verb) not in _flask_routes(root, efile):
                errors.append(f"{eid}: route {route} not registered in {efile}")
        elif kind == "spring":
            want_verb = route.split(" ", 1)[0].upper()
            want_path = _norm_path(route.split(" ", 1)[1])
            if (want_path, want_verb) not in _spring_routes(root, efile):
                errors.append(f"{eid}: route {route} not registered in {efile}")
        elif kind == "cgi":
            want_path = route.split(" ", 1)[1]
            if want_path != "/" + re.sub(r"^cgi-bin/", "", efile):
                errors.append(f"{eid}: route {route} != script path of {efile}")
        elif kind == "registry-cmd":
            wiring = _read(root / "protocol" / "GatewayServer.java")
            if not re.search(rf"::\s*{re.escape(fn)}\b", wiring):
                errors.append(f"{eid}: {fn} not wired in GatewayServer.java")
        elif kind == "bus":
            subject = route.split(" ", 1)[1]
            wiring = _read(root / "ingest" / "runner.py")
            if route.startswith("MSG ") and f'"{subject}"' not in wiring \
                    and f"'{subject}'" not in wiring:
                errors.append(f"{eid}: subject {subject!r} not subscribed in runner.py")
            if not re.search(rf"\b{re.escape(fn)}\b", wiring):
                errors.append(f"{eid}: {fn} not wired in runner.py")

    chain = entry.get("chain") or []
    for c in chain:
        if not (root / c).is_file():
            errors.append(f"{eid}: chain file missing: {c}")
    if entry.get("category") == "A" and entry.get("expected") == "vulnerable":
        sink = entry.get("sink") or {}
        sfile, sfn = sink.get("file"), sink.get("function")
        if not sfile or not sfn or not sink.get("line_hint"):
            errors.append(f"{eid}: category A entry needs sink file/function/line_hint")
        elif not (root / sfile).is_file():
            errors.append(f"{eid}: sink file missing: {sfile}")
        elif sfn not in _functions(root / sfile):
            # Express route sinks live in anonymous handlers; the route
            # registration check above already pins the file.
            if not (kind == "express" and sfile.startswith("routes/")):
                errors.append(f"{eid}: sink function {sfn!r} not found in {sfile}")
        else:
            if chain and chain[0] != efile:
                errors.append(f"{eid}: chain[0] {chain[0]} != entrypoint file")
            if chain and chain[-1] != sfile:
                errors.append(f"{eid}: chain[-1] {chain[-1]} != sink file")


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_ground_truth_structurally_valid(target):
    meta = TARGETS[target]
    root = TARGETS_DIR / target
    gt = json.loads(_read(root / "ground_truth.json"))

    ids = [e.get("id") for e in gt]
    assert len(ids) == len(set(ids)), f"{target}: duplicate ids"

    errors = []
    for entry in gt:
        _check_entry(root, meta["kind"], meta["prefix"], entry, errors)

    md = _read(root / "GROUND_TRUTH.md")
    md_ids = set(re.findall(rf"\b{re.escape(meta['prefix'])}[a-z0-9-]+?\d+", md))
    if md_ids != set(ids):
        errors.append(
            f"{target}: GROUND_TRUTH.md id set != json "
            f"(only-md={sorted(md_ids - set(ids))}, only-json={sorted(set(ids) - md_ids)})")

    assert not errors, f"{target} ground truth problems:\n" + "\n".join(
        f"  - {e}" for e in errors)
