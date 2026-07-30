#!/usr/bin/env python3
"""jsp_to_java.py — deterministic JSP -> Java transpiler.

Neither Semgrep nor Joern has a JSP frontend, so JSP pages are transpiled
into plain-Java servlet-style classes (mirroring what Jasper does) and the
whole existing pipeline (sinks-java.yml, javasrc2cpg, joern scripts) runs on
the generated tree unchanged.

Input tree:
    <input>/pages/**/*.jsp   — transpiled into <out>/pages/<base>_jsp.java
    <input>/src/**/*.java    — copied verbatim into <out>/src/

The transpilation is line-preserving: one output content line per input
line, so JSP line N maps to Java line N + offset. The per-file offset is
recorded in <out>/manifest.json together with the route, e.g.:

    {
      "pages/user_search.jsp": {
        "java": "pages/user_search_jsp.java",
        "offset": 7,
        "route": "/user_search.jsp"
      }
    }

Usage:
    python3 scripts/jsp_to_java.py targets/jsp-legacy -o workspace/jsp-java

Stdlib only. The generated code is never compiled — only parsed — so
unresolved servlet API types are fine.
"""

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

IMPORT_ATTR_RE = re.compile(r"""import\s*=\s*(?:"([^"]*)"|'([^']*)')""")


def handle_directive(body, imports):
    """Collect imports from <%@ page import="a.B, c.D.*" %>; ignore the rest."""
    body = body.strip()
    if not body.startswith("page"):
        return
    m = IMPORT_ATTR_RE.search(body)
    if not m:
        return
    for item in (m.group(1) or m.group(2) or "").split(","):
        item = item.strip()
        if item:
            imp = f"import {item};"
            if imp not in imports:
                imports.append(imp)


def transpile(text):
    """Transpile one JSP file.

    Returns (imports, declarations, content) where content is a list with
    one Java string per source line (template text contributes "").
    """
    n_lines = len(text.split("\n"))
    content = [""] * n_lines
    imports = []
    decls = []

    i = 0
    line = 0
    n = len(text)
    mode = "template"
    buf = ""
    while i < n:
        if mode == "template":
            if text.startswith("<%--", i):
                mode = "comment"
                i += 4
            elif text.startswith("<%@", i):
                mode = "directive"
                buf = ""
                i += 3
            elif text.startswith("<%!", i):
                mode = "declaration"
                buf = ""
                i += 3
            elif text.startswith("<%=", i):
                mode = "expression"
                content[line] += "out.print("
                i += 3
            elif text.startswith("<%", i):
                mode = "scriptlet"
                i += 2
            else:
                if text[i] == "\n":
                    line += 1
                i += 1
        elif mode == "scriptlet":
            if text.startswith("%>", i):
                mode = "template"
                i += 2
            else:
                c = text[i]
                if c == "\n":
                    line += 1
                else:
                    content[line] += c
                i += 1
        elif mode == "expression":
            if text.startswith("%>", i):
                content[line] += ");"
                mode = "template"
                i += 2
            else:
                c = text[i]
                if c == "\n":
                    line += 1
                else:
                    content[line] += c
                i += 1
        elif mode == "declaration":
            if text.startswith("%>", i):
                decls.append(buf)
                mode = "template"
                i += 2
            else:
                c = text[i]
                if c == "\n":
                    buf += "\n"
                    line += 1
                else:
                    buf += c
                i += 1
        elif mode == "directive":
            if text.startswith("%>", i):
                handle_directive(buf, imports)
                mode = "template"
                i += 2
            else:
                c = text[i]
                if c == "\n":
                    buf += "\n"
                    line += 1
                else:
                    buf += c
                i += 1
        elif mode == "comment":
            if text.startswith("--%>", i):
                mode = "template"
                i += 4
            else:
                if text[i] == "\n":
                    line += 1
                i += 1
    return imports, decls, content


def render_java(package, class_name, imports, decls, content):
    """Assemble the generated servlet-style class. Returns (source, offset)."""
    header = [f"package {package};", ""]
    header.extend(imports)
    if imports:
        header.append("")
    header.append(f"public class {class_name} {{")
    for d in decls:
        for dl in d.strip("\n").split("\n"):
            header.append("    " + dl if dl.strip() else "")
    header.append(
        "    public void _jspService(javax.servlet.http.HttpServletRequest request, "
        "javax.servlet.http.HttpServletResponse response) throws Exception {"
    )
    header.append("        java.io.PrintWriter out = response.getWriter();")
    offset = len(header)
    footer = ["    }", "}"]
    return "\n".join(header + content + footer) + "\n", offset


def main():
    ap = argparse.ArgumentParser(description="Transpile JSP pages into plain Java for Semgrep/Joern.")
    ap.add_argument("input", help="target dir containing pages/ and src/")
    ap.add_argument("-o", "--output", default="workspace/jsp-java",
                    help="output dir (default: workspace/jsp-java)")
    args = ap.parse_args()

    in_root = Path(args.input)
    pages_dir = in_root / "pages"
    src_dir = in_root / "src"
    if not pages_dir.is_dir():
        sys.exit(f"error: {pages_dir} not found")
    out_root = Path(args.output)

    # Idempotent: wipe only the dirs this tool manages.
    for managed in (out_root / "pages", out_root / "src"):
        if managed.exists():
            shutil.rmtree(managed)
    (out_root / "pages").mkdir(parents=True, exist_ok=True)

    copied = 0
    if src_dir.is_dir():
        for java in sorted(src_dir.rglob("*.java")):
            rel = java.relative_to(src_dir)
            dest = out_root / "src" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(java, dest)
            copied += 1

    manifest = {}
    for jsp in sorted(pages_dir.rglob("*.jsp")):
        rel = jsp.relative_to(pages_dir)
        base = re.sub(r"[^A-Za-z0-9]", "_", jsp.stem)
        class_name = f"{base}_jsp"
        sub = rel.parent
        package = "jspgen" if str(sub) == "." else "jspgen." + ".".join(sub.parts)

        text = jsp.read_text(encoding="utf-8")
        imports, decls, content = transpile(text)
        source, offset = render_java(package, class_name, imports, decls, content)

        java_rel = Path("pages") / sub / f"{class_name}.java"
        dest = out_root / java_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(source, encoding="utf-8")

        jsp_rel = (Path("pages") / rel).as_posix()
        manifest[jsp_rel] = {
            "java": java_rel.as_posix(),
            "offset": offset,
            "route": "/" + rel.as_posix(),
        }

    (out_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"copied {copied} .java file(s) -> {out_root / 'src'}")
    print(f"transpiled {len(manifest)} .jsp page(s) -> {out_root / 'pages'}")
    print(f"manifest: {out_root / 'manifest.json'}")


if __name__ == "__main__":
    main()
