#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "tree-sitter-language-pack>=0.9",
#     "pathspec>=0.12",
# ]
# ///
"""Repo map generator for the SAST pipeline.

Produces an LLM-consumable "repo map" (Markdown + JSON) for an arbitrary
source repository: annotated directory tree, HTTP route table (Flask /
Express / Spring / ASP.NET heuristics), per-file symbol index (tree-sitter)
and a file-level import reference graph.

Usage:
    uv run scripts/repo_map.py <repo_root> [-o REPO_MAP.md]
        [--json repo_map.json] [--max-tokens N] [--check ground_truth.json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import pathspec
from tree_sitter_language_pack import get_parser

MAX_FILE_BYTES = 512 * 1024
SIG_MAX = 120

LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".cs": "csharp",
}

# Extra extensions listed in the tree but never parsed for symbols.
TEXT_EXTS = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".xml", ".sql",
    ".html", ".css", ".ini", ".cfg", ".properties", ".sh", ".env.example",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__",
    "bin", "obj", "dist", "build", "target", ".idea", ".vscode", "out",
}

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}

ROLE_DIRS = [
    ({"test", "tests", "spec", "specs", "__tests__"}, "test"),
    ({"controller", "controllers", "route", "routes", "api", "endpoints"}, "route"),
    ({"service", "services"}, "service"),
    ({"data", "dao", "model", "models", "repository", "repositories", "db", "entities"}, "data"),
    ({"config", "configs", "configuration", "settings"}, "config"),
    ({"util", "utils", "helper", "helpers", "common", "lib"}, "util"),
]

_parsers: dict[str, object] = {}


def parser_for(language: str):
    if language not in _parsers:
        _parsers[language] = get_parser(language)
    return _parsers[language]


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def node_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        return text[1:-1]
    return text


def string_arg(node, src: bytes) -> str | None:
    """Extract a plain-string literal value from an argument node."""
    for child in node.children:
        if child.type in ("string", "string_literal"):
            return unquote(node_text(child, src))
        if child.type == "attribute_argument" or child.type == "argument_list":
            v = string_arg(child, src)
            if v is not None:
                return v
    return None


def signature(node, src: bytes) -> str:
    body = node.child_by_field_name("body")
    end = body.start_byte if body else node.end_byte
    sig = " ".join(src[node.start_byte:end].decode("utf-8", "replace").split())
    if len(sig) > SIG_MAX:
        sig = sig[: SIG_MAX - 3] + "..."
    return sig


def camel(name: str) -> str:
    parts = [p for p in re.split(r"[_\-]+", name) if p]
    if not parts:
        return "handler"
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def join_route(prefix: str, path: str) -> str:
    joined = "/".join(s.strip("/") for s in (prefix, path) if s.strip("/"))
    return "/" + joined if joined else "/"


def derive_handler_name(path: str) -> str:
    """Derive a stable name for anonymous route handlers from the path."""
    segs = [s for s in path.split("/") if s and not s.startswith(":")
            and not s.startswith("{")]
    return camel(segs[-1]) if segs else "handler"


def role_for(rel_path: str) -> str:
    parts = Path(rel_path).parts
    segs = {s.lower() for s in parts[:-1]}
    stem = Path(parts[-1]).stem.lower()
    for keys, role in ROLE_DIRS:
        if segs & keys or stem in keys:
            return role
    return "other"


# ---------------------------------------------------------------------------
# Per-language symbol / import / route extraction
# ---------------------------------------------------------------------------

CLASS_TYPES = {
    "class_declaration", "class_definition", "interface_declaration",
    "enum_declaration",
}
FUNC_TYPES = {
    "function_definition", "function_declaration",
    "generator_function_declaration", "method_declaration",
    "method_definition",
}


def extract_python(tree, src: bytes):
    imports, symbols, routes = [], [], []
    bp_prefix: dict[str, str] = {}

    def is_string(node):
        return node.type == "string"

    root = tree.root_node
    # Blueprint assignments: x = Blueprint("name", ..., url_prefix="/p")
    for node in root.children:
        if node.type != "assignment":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not (left and right and right.type == "call"):
            continue
        func = right.child_by_field_name("function")
        if not func or node_text(func, src) != "Blueprint":
            continue
        args = right.child_by_field_name("arguments")
        prefix = ""
        for kw in args.children:
            if kw.type == "keyword_argument":
                key = kw.child_by_field_name("name")
                val = kw.child_by_field_name("value")
                if key and node_text(key, src) == "url_prefix" and val:
                    prefix = unquote(node_text(val, src))
        bp_prefix[node_text(left, src)] = prefix

    def handle_route_decorator(dec, fname, fnode):
        call = dec.children[1] if len(dec.children) > 1 else None
        if call is None or call.type != "call":
            return
        func = call.child_by_field_name("function")
        if not func or func.type != "attribute":
            return
        obj = func.child_by_field_name("object")
        attr = func.child_by_field_name("attribute")
        if not obj or not attr:
            return
        var, method_attr = node_text(obj, src), node_text(attr, src)
        if var not in bp_prefix and var != "app":
            return
        if method_attr != "route" and method_attr not in HTTP_METHODS:
            return
        args = call.child_by_field_name("arguments")
        if not args:
            return
        path = None
        methods = []
        for a in args.children:
            if is_string(a) and path is None:
                path = unquote(node_text(a, src))
            elif a.type == "keyword_argument":
                key = a.child_by_field_name("name")
                val = a.child_by_field_name("value")
                if key and node_text(key, src) == "methods" and val:
                    methods = [unquote(node_text(s, src)).upper()
                               for s in val.children if is_string(s)]
        if path is None:
            return
        if method_attr != "route":
            methods = [method_attr.upper()]
        if not methods:
            methods = ["GET"]
        for m in methods:
            routes.append({
                "method": m,
                "path": join_route(bp_prefix.get(var, ""), path),
                "function": fname,
                "line": dec.start_point[0] + 1,
            })

    def visit_defs(node, parent):
        for child in node.children:
            if child.type == "decorated_definition":
                definition = child.child_by_field_name("definition")
                if not definition:
                    continue
                name_node = definition.child_by_field_name("name")
                fname = node_text(name_node, src) if name_node else "?"
                kind = "class" if definition.type == "class_definition" else "function"
                symbols.append({
                    "kind": kind, "name": fname,
                    "signature": signature(definition, src),
                    "line": definition.start_point[0] + 1, "parent": parent,
                })
                if kind == "function":
                    for dec in child.children:
                        if dec.type == "decorator":
                            handle_route_decorator(dec, fname, definition)
                elif kind == "class":
                    visit_defs(definition.child_by_field_name("body") or definition, fname)
            elif child.type == "function_definition":
                name_node = child.child_by_field_name("name")
                symbols.append({
                    "kind": "method" if parent else "function",
                    "name": node_text(name_node, src) if name_node else "?",
                    "signature": signature(child, src),
                    "line": child.start_point[0] + 1, "parent": parent,
                })
            elif child.type == "class_definition":
                name_node = child.child_by_field_name("name")
                cname = node_text(name_node, src) if name_node else "?"
                symbols.append({
                    "kind": "class", "name": cname,
                    "signature": signature(child, src),
                    "line": child.start_point[0] + 1, "parent": parent,
                })
                visit_defs(child.child_by_field_name("body") or child, cname)

    visit_defs(root, None)

    for node in root.children:
        if node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    imports.append(node_text(child, src))
        elif node.type == "import_from_statement":
            mod = node.child_by_field_name("module_name")
            if mod:
                imports.append(node_text(mod, src))
    # resolution hints: "module.name" for each `from module import name`,
    # so `from data import db` can resolve to data/db.py (not shown in output)
    hints = []
    for node in root.children:
        if node.type != "import_from_statement":
            continue
        mod = node.child_by_field_name("module_name")
        if not mod:
            continue
        module = node_text(mod, src)
        for c in node.children:
            name_node = None
            if c.type == "dotted_name" and c != mod:
                name_node = c
            elif c.type == "aliased_import":
                name_node = next((x for x in c.children if x.type == "dotted_name"), None)
            if name_node is not None:
                hints.append(f"{module}.{node_text(name_node, src)}")
    return imports, symbols, routes, hints


def extract_js_ts(tree, src: bytes):
    imports, symbols, routes = [], [], []
    require_map: dict[str, str] = {}   # local var -> module specifier
    mounts: list[tuple[str, str]] = []  # (prefix, router var)

    def visit(node, parent, depth):
        for child in node.children:
            t = child.type
            if t == "export_statement":
                visit(child, parent, depth)
            elif depth == 0 and t in CLASS_TYPES:
                name_node = child.child_by_field_name("name")
                cname = node_text(name_node, src) if name_node else "?"
                kind = "interface" if t == "interface_declaration" else "class"
                symbols.append({
                    "kind": kind, "name": cname,
                    "signature": signature(child, src),
                    "line": child.start_point[0] + 1, "parent": parent,
                })
                body = child.child_by_field_name("body")
                if body:
                    visit(body, cname, depth + 1)
            elif t in ("function_declaration", "generator_function_declaration"):
                name_node = child.child_by_field_name("name")
                symbols.append({
                    "kind": "method" if parent else "function",
                    "name": node_text(name_node, src) if name_node else "?",
                    "signature": signature(child, src),
                    "line": child.start_point[0] + 1, "parent": parent,
                })
            elif t == "method_definition":
                name_node = child.child_by_field_name("name")
                symbols.append({
                    "kind": "method",
                    "name": node_text(name_node, src) if name_node else "?",
                    "signature": signature(child, src),
                    "line": child.start_point[0] + 1, "parent": parent,
                })
            elif depth == 0 and t == "lexical_declaration":
                for dec in child.children:
                    if dec.type != "variable_declarator":
                        continue
                    name_node = dec.child_by_field_name("name")
                    value = dec.child_by_field_name("value")
                    if not name_node or not value:
                        continue
                    if value.type == "call_expression":
                        fn = value.child_by_field_name("function")
                        if fn and fn.type == "identifier" and node_text(fn, src) == "require":
                            args = value.child_by_field_name("arguments")
                            spec = string_arg(args, src) if args else None
                            if spec:
                                require_map[node_text(name_node, src)] = spec
                                imports.append(spec)
                    elif value.type in ("arrow_function", "function_expression"):
                        symbols.append({
                            "kind": "function", "name": node_text(name_node, src),
                            "signature": signature(value, src),
                            "line": dec.start_point[0] + 1, "parent": parent,
                        })
            elif t == "import_statement":
                spec = None
                local = None
                for c in child.children:
                    if c.type == "string":
                        spec = unquote(node_text(c, src))
                    elif c.type == "import_clause":
                        for cc in c.children:
                            if cc.type == "identifier":
                                local = node_text(cc, src)
                if spec:
                    imports.append(spec)
                    if local:
                        require_map[local] = spec
            elif t == "expression_statement":
                for c in child.children:
                    if c.type == "call_expression":
                        handle_call(c)
            elif t == "call_expression":
                handle_call(child)

    def handle_call(call):
        fn = call.child_by_field_name("function")
        if not fn or fn.type != "member_expression":
            return
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        if not obj or not prop or obj.type != "identifier":
            return
        method = node_text(prop, src)
        args = call.child_by_field_name("arguments")
        if not args:
            return
        str_args = [a for a in args.children if a.type == "string"]
        if method == "use":
            # app.use('/prefix', routerVar)
            if str_args:
                ids = [a for a in args.children if a.type == "identifier"]
                if ids:
                    mounts.append((unquote(node_text(str_args[0], src)),
                                   node_text(ids[-1], src)))
            return
        if method not in HTTP_METHODS or not str_args:
            return
        path = unquote(node_text(str_args[0], src))
        handler = None
        for a in args.children:
            if a.type == "identifier":
                handler = node_text(a, src)
            elif a.type in ("arrow_function", "function_expression"):
                handler = derive_handler_name(path)
        if handler is None:
            handler = derive_handler_name(path)
        routes.append({
            "method": method.upper(), "path": path, "function": handler,
            "line": call.start_point[0] + 1,
        })

    visit(tree.root_node, None, 0)
    return imports, symbols, routes, require_map, mounts


JAVA_MAPPING = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "DeleteMapping": "DELETE", "PatchMapping": "PATCH",
}


def extract_java(tree, src: bytes):
    imports, symbols, routes = [], [], []

    for node in tree.root_node.children:
        if node.type == "import_declaration":
            text = node_text(node, src).strip().rstrip(";")
            imports.append(text.replace("import", "").strip())

    def annotation_info(ann):
        name_node = ann.child_by_field_name("name")
        name = node_text(name_node, src).split(".")[-1] if name_node else ""
        path, method = None, None
        args = ann.child_by_field_name("arguments")
        if args:
            for c in args.children:
                if c.type == "string_literal" and path is None:
                    path = unquote(node_text(c, src))
                elif c.type == "element_value_pair":
                    key = c.child_by_field_name("key")
                    val = c.child_by_field_name("value")
                    k = node_text(key, src) if key else ""
                    if k in ("value", "path") and val and val.type == "string_literal":
                        path = unquote(node_text(val, src))
                    elif k == "method" and val:
                        m = re.search(r"RequestMethod\.(\w+)", node_text(val, src))
                        if m:
                            method = m.group(1).upper()
        return name, path, method

    def class_annotations(cls):
        out = []
        mods = next((c for c in cls.children if c.type == "modifiers"), None)
        if mods:
            for c in mods.children:
                if c.type in ("annotation", "marker_annotation"):
                    out.append(annotation_info(c))
        return out

    def visit(node, parent):
        for child in node.children:
            if child.type in CLASS_TYPES:
                name_node = child.child_by_field_name("name")
                cname = node_text(name_node, src) if name_node else "?"
                kind = {"class_declaration": "class",
                        "interface_declaration": "interface",
                        "enum_declaration": "class"}[child.type]
                symbols.append({
                    "kind": kind, "name": cname,
                    "signature": signature(child, src),
                    "line": child.start_point[0] + 1, "parent": parent,
                })
                prefix = ""
                for aname, apath, _ in class_annotations(child):
                    if aname == "RequestMapping" and apath:
                        prefix = apath
                body = child.child_by_field_name("body")
                if body:
                    for m in body.children:
                        if m.type != "method_declaration":
                            continue
                        mname_node = m.child_by_field_name("name")
                        mname = node_text(mname_node, src) if mname_node else "?"
                        symbols.append({
                            "kind": "method", "name": mname,
                            "signature": signature(m, src),
                            "line": m.start_point[0] + 1, "parent": cname,
                        })
                        mods = next((c for c in m.children if c.type == "modifiers"), None)
                        anns = []
                        if mods:
                            anns = [c for c in mods.children
                                    if c.type in ("annotation", "marker_annotation")]
                        for ann in anns:
                            aname, apath, amethod = annotation_info(ann)
                            if aname in JAVA_MAPPING or aname == "RequestMapping":
                                http = JAVA_MAPPING.get(aname) or amethod
                                if http and apath is not None:
                                    routes.append({
                                        "method": http,
                                        "path": join_route(prefix, apath),
                                        "function": mname,
                                        "line": ann.start_point[0] + 1,
                                    })
            elif child.type in ("class_declaration",):
                continue

    visit(tree.root_node, None)
    return imports, symbols, routes


CS_HTTP = {
    "HttpGet": "GET", "HttpPost": "POST", "HttpPut": "PUT",
    "HttpDelete": "DELETE", "HttpPatch": "PATCH",
}


def extract_csharp(tree, src: bytes):
    imports, symbols, routes = [], [], []

    def attr_info(attr_list):
        out = []
        for attr in attr_list.children:
            if attr.type != "attribute":
                continue
            name_node = attr.child_by_field_name("name")
            name = node_text(name_node, src).split(".")[-1] if name_node else ""
            path = None
            args = next((c for c in attr.children
                         if c.type == "attribute_argument_list"), None)
            if args:
                path = string_arg(args, src)
            out.append((name, path, attr.start_point[0] + 1))
        return out

    def visit(node, parent):
        for child in node.children:
            if child.type == "using_directive":
                text = node_text(child, src).strip().rstrip(";")
                imports.append(text.replace("using", "").strip())
            elif child.type in ("namespace_declaration",
                                "file_scoped_namespace_declaration",
                                "declaration_list"):
                visit(child, parent)
            elif child.type in CLASS_TYPES:
                name_node = child.child_by_field_name("name")
                cname = node_text(name_node, src) if name_node else "?"
                kind = "interface" if child.type == "interface_declaration" else "class"
                symbols.append({
                    "kind": kind, "name": cname,
                    "signature": signature(child, src),
                    "line": child.start_point[0] + 1, "parent": parent,
                })
                prefix = ""
                for c in child.children:
                    if c.type == "attribute_list":
                        for aname, apath, _ in attr_info(c):
                            if aname == "Route" and apath:
                                prefix = apath
                body = child.child_by_field_name("body")
                if body:
                    visit_methods(body, cname, prefix)

    def visit_methods(body, cname, prefix):
        for m in body.children:
            if m.type != "method_declaration":
                if m.type in CLASS_TYPES:
                    visit(m, cname)
                continue
            name_node = m.child_by_field_name("name")
            mname = node_text(name_node, src) if name_node else "?"
            symbols.append({
                "kind": "method", "name": mname,
                "signature": signature(m, src),
                "line": m.start_point[0] + 1, "parent": cname,
            })
            http, path, line = None, None, None
            for c in m.children:
                if c.type != "attribute_list":
                    continue
                for aname, apath, aline in attr_info(c):
                    if aname in CS_HTTP:
                        http = CS_HTTP[aname]
                        if apath is not None:
                            path, line = apath, aline
                    elif aname == "Route" and apath is not None:
                        path, line = apath, aline
            if http and path is not None:
                routes.append({
                    "method": http,
                    "path": join_route(prefix, path),
                    "function": mname,
                    "line": line,
                })

    visit(tree.root_node, None)
    return imports, symbols, routes


# ---------------------------------------------------------------------------
# Repo walking and import resolution
# ---------------------------------------------------------------------------

def load_gitignore(root: Path):
    spec_lines = []
    gi = root / ".gitignore"
    if gi.is_file():
        spec_lines = gi.read_text(errors="replace").splitlines()
    return pathspec.PathSpec.from_lines("gitwildmatch", spec_lines)


def walk_repo(root: Path):
    spec = load_gitignore(root)
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
            and not spec.match_file(os.path.relpath(os.path.join(dirpath, d), root) + "/")
        )
        for fn in sorted(filenames):
            if fn.startswith("."):
                continue
            full = Path(dirpath) / fn
            rel = full.relative_to(root).as_posix()
            if spec.match_file(rel):
                continue
            try:
                size = full.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                continue
            ext = full.suffix.lower()
            language = LANG_BY_EXT.get(ext)
            if language is None and ext not in TEXT_EXTS:
                continue
            files.append({"path": rel, "abs": full, "language": language})
    return files


def resolve_import(specifier: str, from_rel: str, all_paths: set[str],
                   language: str) -> str | None:
    """Resolve an import specifier to a repo-relative file path."""
    if language == "python":
        mod = specifier.replace(".", "/")
        candidates = [mod + ".py", mod + "/__init__.py"]
        # from X import name -> X/name.py is resolved by caller via name hint
        for cand in candidates:
            if cand in all_paths:
                return cand
        return None
    if language in ("javascript", "typescript"):
        if not specifier.startswith("."):
            return None
        base = Path(from_rel).parent
        target = (base / specifier).as_posix()
        norm = os.path.normpath(target).replace(os.sep, "/")
        for cand in (norm, norm + ".js", norm + ".ts", norm + ".jsx",
                     norm + ".tsx", norm + "/index.js", norm + "/index.ts"):
            if cand in all_paths:
                return cand
        return None
    if language == "java":
        parts = specifier.split(".")
        for i in range(len(parts)):
            cand = "/".join(parts[i:]) + ".java"
            if cand in all_paths:
                return cand
            hits = [p for p in all_paths if p.endswith("/" + cand)]
            if hits:
                return sorted(hits)[0]
        return None
    if language == "csharp":
        parts = specifier.split(".")
        for i in range(len(parts)):
            cand = "/".join(parts[i:]) + ".cs"
            if cand in all_paths:
                return cand
            hits = [p for p in all_paths if p.endswith("/" + cand)]
            if hits:
                return sorted(hits)[0]
        # using X.Y.Namespace -> all sources under directory <Namespace>/
        last = parts[-1]
        hits = [p for p in all_paths
                if ("/" + last + "/") in p or p.startswith(last + "/")]
        if hits:
            return sorted(hits)[0]
        return None
    return None


def build_map(root: Path) -> dict:
    root = root.resolve()
    walked = walk_repo(root)
    all_paths = {f["path"] for f in walked}
    files_out = []
    references: set[tuple[str, str]] = set()
    js_pending: list[dict] = []   # js/ts file results awaiting mount prefixes
    mount_prefix: dict[str, str] = {}  # repo file -> url prefix (express)

    results: dict[str, dict] = {}
    for f in walked:
        if f["language"] is None:
            continue
        src = f["abs"].read_bytes()
        try:
            tree = parser_for(f["language"]).parse(src)
        except Exception as exc:  # graceful degradation
            print(f"warn: parse failed for {f['path']}: {exc}", file=sys.stderr)
            results[f["path"]] = {"imports": [], "symbols": [], "routes": []}
            continue
        lang = f["language"]
        if lang == "python":
            imports, symbols, routes, hints = extract_python(tree, src)
            extra = {"hints": hints}
        elif lang in ("javascript", "typescript"):
            imports, symbols, routes, require_map, mounts = extract_js_ts(tree, src)
            extra = {"require_map": require_map, "mounts": mounts}
            js_pending.append({"path": f["path"], "routes": routes})
        elif lang == "java":
            imports, symbols, routes = extract_java(tree, src)
            extra = {}
        else:
            imports, symbols, routes = extract_csharp(tree, src)
            extra = {}
        results[f["path"]] = {
            "imports": imports, "symbols": symbols, "routes": routes, **extra,
        }

    # Express: apply app.use('/prefix', router) mount prefixes cross-file.
    for f in walked:
        res = results.get(f["path"])
        if not res or "mounts" not in res:
            continue
        for prefix, var in res["mounts"]:
            spec = res["require_map"].get(var)
            if not spec:
                continue
            target = resolve_import(spec, f["path"], all_paths, f["language"])
            if target:
                mount_prefix[target] = join_route(prefix, mount_prefix.get(target, ""))

    for f in walked:
        if f["language"] is None:
            continue
        res = results[f["path"]]
        routes = res["routes"]
        if f["path"] in mount_prefix:
            routes = [dict(r, path=join_route(mount_prefix[f["path"]], r["path"]))
                      for r in routes]
        files_out.append({
            "path": f["path"],
            "role": role_for(f["path"]),
            "language": f["language"],
            "imports": res["imports"],
            "symbols": res["symbols"],
            "routes": routes,
        })

    for f in files_out:
        specs = list(f["imports"]) + results[f["path"]].get("hints", [])
        for spec in specs:
            target = resolve_import(spec, f["path"], all_paths, f["language"])
            if target and target != f["path"]:
                references.add((f["path"], target))

    return {
        "root": str(root),
        "tool": "tree-sitter",
        "files": files_out,
        "references": [{"from": a, "to": b} for a, b in sorted(references)],
    }


# ---------------------------------------------------------------------------
# Markdown rendering (with rough token-budget truncation)
# ---------------------------------------------------------------------------

def est_tokens(text: str) -> int:
    return len(text) // 4


def render_tree(paths: list[str], roles: dict[str, str]) -> str:
    tree: dict = {}
    for p in paths:
        node = tree
        for part in p.split("/"):
            node = node.setdefault(part, {})
    lines = []

    def emit(node, prefix):
        items = sorted(node.items(), key=lambda kv: (bool(kv[1]), kv[0]))
        for i, (name, children) in enumerate(items):
            last = i == len(items) - 1
            connector = "└── " if last else "├── "
            if children:
                lines.append(prefix + connector + name + "/")
                emit(children, prefix + ("    " if last else "│   "))
            else:
                full = None
                # recover full path for role lookup lazily
                role = roles.get(name)
                suffix = f"  [{role}]" if role else ""
                lines.append(prefix + connector + name + suffix)

    # role lookup needs full path; build a basename->role map first
    base_roles: dict[str, str] = {}
    for p, r in roles.items():
        base_roles.setdefault(p.split("/")[-1], r)
    roles.clear()
    roles.update(base_roles)
    emit(tree, "")
    return "\n".join(lines)


def render_markdown(data: dict, max_tokens: int | None) -> str:
    files = data["files"]
    roles = {f["path"]: f["role"] for f in files}
    header = [
        f"# Repo Map: {Path(data['root']).name}",
        "",
        f"Root: `{data['root']}`  ",
        f"Tool: {data['tool']}  ",
        f"Files indexed: {len(files)}",
        "",
    ]
    tree_sec = ["## Directory Tree", "", "```",
                render_tree([f["path"] for f in files], dict(roles)), "```", ""]

    route_rows = ["## HTTP Routes", "",
                  "| Method | Path | File | Function | Line |",
                  "|---|---|---|---|---|"]
    all_routes = []
    for f in files:
        for r in f["routes"]:
            all_routes.append((r["method"], r["path"], f["path"],
                               r["function"], r["line"]))
    for m, p, fp, fn, ln in sorted(all_routes, key=lambda x: (x[2], x[4])):
        route_rows.append(f"| {m} | `{p}` | {fp} | `{fn}` | {ln} |")
    route_rows.append("")

    inbound: dict[str, int] = {}
    for ref in data["references"]:
        inbound[ref["to"]] = inbound.get(ref["to"], 0) + 1

    file_secs: dict[str, list[str]] = {}
    for f in files:
        sec = [f"### {f['path']}  ({f['role']}, {f['language']})"]
        if f["imports"]:
            sec.append("- imports: " + ", ".join(f"`{i}`" for i in f["imports"]))
        for s in f["symbols"]:
            parent = f" (in {s['parent']})" if s.get("parent") else ""
            sec.append(f"- L{s['line']} `{s['kind']}` **{s['name']}**{parent}: "
                       f"`{s['signature']}`")
        if not f["symbols"]:
            sec.append("- (no top-level symbols)")
        sec.append("")
        file_secs[f["path"]] = sec

    ref_lines = ["## Reference Graph", ""]
    for ref in data["references"]:
        ref_lines.append(f"- {ref['from']} → {ref['to']}")
    ref_lines.append("")
    hot = sorted(inbound.items(), key=lambda kv: -kv[1])[:10]
    if hot:
        ref_lines.append("Most referenced: " + ", ".join(
            f"`{p}` ({n})" for p, n in hot))
        ref_lines.append("")

    def assemble(include: list[str]) -> str:
        parts = header + tree_sec + route_rows
        for p in include:
            parts += file_secs[p]
        parts += ref_lines
        return "\n".join(parts) + "\n"

    order = [f["path"] for f in files]
    md = assemble(order)
    if max_tokens and est_tokens(md) > max_tokens:
        # Drop per-file symbol sections, least-referenced first, keeping
        # files that carry routes and heavily referenced files longest.
        ranked = sorted(order,
                        key=lambda p: (inbound.get(p, 0),
                                       bool(file_secs and any(
                                           r for r in next(
                                               x for x in files if x["path"] == p
                                           )["routes"]))))
        dropped = []
        for p in ranked:
            if est_tokens(md) <= max_tokens:
                break
            dropped.append(p)
            md = assemble([x for x in order if x not in dropped])
        if dropped:
            md += (f"\n_Note: {len(dropped)} file section(s) omitted to fit "
                   f"--max-tokens {max_tokens}: {', '.join(dropped)}_\n")
    return md


# ---------------------------------------------------------------------------
# Ground-truth cross-check
# ---------------------------------------------------------------------------

def norm_route(method: str, path: str) -> tuple[str, str]:
    p = re.sub(r"<[^>]+>", "{}", path)      # flask <int:id>
    p = re.sub(r":[^/]+", "{}", p)          # express :id
    p = re.sub(r"\{[^}]+\}", "{}", p)       # spring/aspnet {id}
    p = re.sub(r"/+", "/", p).rstrip("/") or "/"
    return method.upper(), p


def check_ground_truth(data: dict, gt_path: str) -> None:
    gt = json.loads(Path(gt_path).read_text())
    extracted = []
    for f in data["files"]:
        for r in f["routes"]:
            extracted.append((f["path"], r))
    route_hit = func_hit = total = 0
    misses = []
    for entry in gt:
        ep = entry.get("entrypoint") or {}
        route = ep.get("route")
        if not route:
            continue
        total += 1
        method, _, path = route.partition(" ")
        want = norm_route(method, path)
        match = next(((fp, r) for fp, r in extracted
                      if norm_route(r["method"], r["path"]) == want), None)
        if not match:
            misses.append(f"ROUTE MISS  {entry['id']}: {route} ({ep.get('file')})")
            continue
        route_hit += 1
        fp, r = match
        if ep.get("function") == r["function"]:
            func_hit += 1
        else:
            misses.append(
                f"FUNC MISS   {entry['id']}: {route} want `{ep.get('function')}`"
                f" got `{r['function']}` ({fp})")
    print(f"ground truth: {gt_path}")
    print(f"  route hits:    {route_hit}/{total}"
          f" ({100.0 * route_hit / max(total, 1):.1f}%)")
    print(f"  function hits: {func_hit}/{total}"
          f" ({100.0 * func_hit / max(total, 1):.1f}%)")
    for m in misses:
        print("  " + m)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Generate an LLM-consumable repo map.")
    ap.add_argument("repo_root", help="repository root directory")
    ap.add_argument("-o", "--output", default="REPO_MAP.md",
                    help="markdown output path (default: REPO_MAP.md)")
    ap.add_argument("--json", dest="json_out", default=None,
                    help="optional JSON output path")
    ap.add_argument("--max-tokens", type=int, default=None,
                    help="rough token budget for the markdown (4 chars/token)")
    ap.add_argument("--check", default=None,
                    help="ground_truth.json to cross-check routes/functions against")
    args = ap.parse_args()

    root = Path(args.repo_root)
    if not root.is_dir():
        ap.error(f"not a directory: {root}")
    data = build_map(root)

    md = render_markdown(data, args.max_tokens)
    Path(args.output).write_text(md)
    print(f"markdown -> {args.output} ({est_tokens(md)} est. tokens)")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(data, indent=2) + "\n")
        print(f"json     -> {args.json_out}")

    if args.check:
        check_ground_truth(data, args.check)


if __name__ == "__main__":
    main()
