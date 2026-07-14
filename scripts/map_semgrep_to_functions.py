#!/usr/bin/env python3
"""Map Semgrep findings to their enclosing function/method definitions via AST.

Semgrep reports sink call sites (e.g. `session.execute(...)`).  For downstream
function-level taint analysis we usually want the *enclosing function* (e.g.
`run_query`).  This script reads Semgrep JSON output and produces that mapping.
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Location:
    path: Path
    line: int


@dataclass
class EnclosingScope:
    kind: str  # "function" | "method" | "module"
    name: str | None
    class_name: str | None = None
    lineno: int | None = None


def _qualified_name(node: ast.FunctionDef | ast.AsyncFunctionDef, class_name: str | None) -> str:
    name = node.name
    if class_name:
        return f"{class_name}.{name}"
    return name


def _function_id(path: str, scope: EnclosingScope) -> str:
    """Return a unique, stable identifier for the enclosing function definition."""
    if scope.kind == "module":
        return f"{path}:<module>"
    def_line = scope.lineno if scope.lineno else "?"
    name = scope.name or "<anonymous>"
    return f"{path}:{def_line}:{name}"


def _find_scope(tree: ast.AST, target_line: int) -> EnclosingScope:
    """Return the innermost function/method containing `target_line`."""
    best: EnclosingScope = EnclosingScope(kind="module", name=None)

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if node.lineno <= target_line:
                # A class can be the closest scope if no method covers the line.
                # We keep it only as a fallback; methods override it below.
                if best.kind == "module":
                    best = EnclosingScope(kind="class", name=node.name, lineno=node.lineno)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= target_line:
                # Compute end line using the last statement if available,
                # otherwise fall back to the function's first line.
                end_lineno = node.end_lineno
                if end_lineno is None and node.body:
                    end_lineno = getattr(node.body[-1], "end_lineno", None)
                if end_lineno is None:
                    end_lineno = node.lineno

                if target_line <= end_lineno:
                    # Determine whether this function sits inside a class.
                    class_name = _nearest_class_name(tree, node)
                    kind = "method" if class_name else "function"
                    best = EnclosingScope(
                        kind=kind,
                        name=_qualified_name(node, class_name),
                        class_name=class_name,
                        lineno=node.lineno,
                    )

    return best


def _nearest_class_name(tree: ast.AST, target: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Return the name of the innermost class that contains `target`."""
    best: str | None = None
    best_lineno = -1

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if node.lineno <= target.lineno:
                end = getattr(node, "end_lineno", None)
                if end is None and node.body:
                    end = getattr(node.body[-1], "end_lineno", None)
                if end is None:
                    end = node.lineno
                if target.lineno <= end and node.lineno > best_lineno:
                    best = node.name
                    best_lineno = node.lineno
    return best


def _load_ast(path: Path) -> ast.AST | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        print(f"warning: could not parse {path}: {exc}", file=sys.stderr)
        return None


def map_findings(semgrep_json: dict[str, Any]) -> list[tuple[dict[str, Any], EnclosingScope]]:
    """Pair each Semgrep result with its enclosing scope."""
    cache: dict[Path, ast.AST | None] = {}
    out: list[tuple[dict[str, Any], EnclosingScope]] = []

    for result in semgrep_json.get("results", []):
        path = Path(result["path"])
        line = result["start"]["line"]

        tree = cache.get(path)
        if path not in cache:
            tree = _load_ast(path)
            cache[path] = tree

        if tree is None:
            out.append((result, EnclosingScope(kind="module", name=None)))
            continue

        scope = _find_scope(tree, line)
        out.append((result, scope))

    return out


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) != 1:
        print(f"usage: {sys.argv[0]} <semgrep-results.json>", file=sys.stderr)
        return 2

    json_path = Path(argv[0])
    data = json.loads(json_path.read_text(encoding="utf-8"))
    mapped = map_findings(data)

    # Header
    print(f"{'FILE:LINE':<35} {'FUNCTION_ID':<55} {'RULE'}")
    print("-" * 110)

    for result, scope in mapped:
        loc = f"{result['path']}:{result['start']['line']}"
        func_id = _function_id(result["path"], scope)
        rule = result["check_id"].split(".")[-1]
        print(f"{loc:<35} {func_id:<55} {rule}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
