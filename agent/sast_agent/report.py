"""Findings report + ground-truth scoring for the SAST agent (M2).

Reads findings JSONL (one contracts.Finding per line), writes a concise
Markdown report, and scores the findings against the target's
ground_truth.json with the same matching logic as
scripts/llm_judge_sink_chains.py (file+function matching, route-suffix
matching, _jsp.java -> .jsp normalization — copied below with attribution).

Also owns the confidence_level mapping (plan §4): provisional for M2,
refined by the M4 verifier.

CLI:
    python3 -m agent.sast_agent.report --findings findings.jsonl \
        --ground-truth targets/python-flask/ground_truth.json -o report.md
"""

import argparse
import json
import sys

from .contracts import Gap, InvestigationBrief, Verdict


def assign_confidence_level(brief: InvestigationBrief, verdict: Verdict) -> str:
    """Provisional M2 mapping (plan §4).

    M4 refines it afterwards: apply_verifier() merges the attacker/defender
    rounds into the level (attacker failure downgrades, an effective
    defender-cited sanitizer vetoes the verdict).
    """
    if verdict.is_vulnerable:
        if brief.gap == Gap.OK and brief.taint and brief.taint.confirmed:
            return "CONFIRMED"
        return "LIKELY"
    return "SUSPICIOUS"


def assign_confidence_level_b(verdict: Verdict, evidence: list) -> str:
    """Initial M7 mapping for category-B findings (plan §4). The verifier
    rounds refine it afterwards (apply_verifier_b: attacker failure
    downgrades, defender guard vetoes).

    - CONFIRMED: vulnerable AND absence-comparison evidence with >=2
      parseable file:line refs (where the check is missing + where a
      sibling has it);
    - LIKELY: vulnerable but the comparison evidence is incomplete;
    - not-vulnerable findings stay out of the grading (SUSPICIOUS, same
      convention as A-class).
    """
    if not verdict.is_vulnerable:
        return "SUSPICIOUS"
    n_refs = 0
    for e in evidence:
        kind = e.get("kind") if isinstance(e, dict) else getattr(e, "kind", "")
        if kind != "absence_comparison":
            continue
        refs = e.get("refs", []) if isinstance(e, dict) else getattr(e, "refs", [])
        n_refs += sum(1 for ref in refs if _REF_RE.search(ref.strip()))
    return "CONFIRMED" if n_refs >= 2 else "LIKELY"


# ---------------------------------------------------------------------------
# Matching logic copied from scripts/llm_judge_sink_chains.py (kept in sync):
# simple_name / cpg_file / route_matches / chain_matches_entry operate on the
# judge's verdict shape; _finding_as_verdict adapts a Finding to it.
# ---------------------------------------------------------------------------

import re


def simple_name(full_name: str) -> str:
    """CPG method fullName -> bare method name (copied from
    scripts/llm_judge_sink_chains.py)."""
    if ":<module>." in full_name:
        return full_name.rsplit(".", 1)[-1]
    base = full_name.split(":", 1)[0]  # strip :returntype(params)
    return base.rsplit(".", 1)[-1] or full_name


def cpg_file(path: str) -> str:
    """Transpiled-JSP page name back to ground-truth name (copied from
    scripts/llm_judge_sink_chains.py)."""
    return re.sub(r"_jsp\.java$", ".jsp", path)


_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH")
_ANNO_METHODS = (
    ("HTTPDELETE", "DELETE"), ("HTTPPATCH", "PATCH"), ("HTTPGET", "GET"),
    ("HTTPPOST", "POST"), ("HTTPPUT", "PUT"),
    ("DELETEMAPPING", "DELETE"), ("PATCHMAPPING", "PATCH"),
    ("GETMAPPING", "GET"), ("POSTMAPPING", "POST"), ("PUTMAPPING", "PUT"),
)


def _ep_method(ep: str) -> str:
    up = ep.upper()
    for anno, m in _ANNO_METHODS:
        if anno in up:
            return m
    for m in _HTTP_METHODS:
        if re.search(rf"\b{m}\b", up):
            return m
    return ""


def _norm_segs(path: str) -> list[str]:
    """'/users/:id' -> ['users', '*'] (copied)."""
    return [
        "*" if s.startswith((":", "{", "<")) else s
        for s in path.split("/") if s
    ]


def route_matches(gt_route: str, ep: str) -> bool:
    """Match a ground-truth route ('GET /users/search') against a chain
    entrypoint label (copied from scripts/llm_judge_sink_chains.py)."""
    parts = gt_route.split(None, 1)
    if len(parts) != 2:
        return gt_route.upper() in ep.upper()
    method, path = parts[0].upper(), parts[1]
    m = _ep_method(ep)
    if m and m != method:
        return False
    gt_segs = _norm_segs(path)
    cand: list[str] = []
    for frag in re.findall(r'"([^"]*)"', ep):
        cand.extend(_norm_segs(frag))
    if not cand:
        return False
    return len(cand) <= len(gt_segs) and gt_segs[-len(cand):] == cand


def chain_matches_entry(record: dict, chain: dict, entry: dict) -> bool:
    """Does this sink+chain correspond to the ground-truth entry?
    (copied from scripts/llm_judge_sink_chains.py)."""
    if record["sink"].get("vuln_type") != entry.get("vuln_type"):
        return False
    gt_sink = entry.get("sink")
    ep = chain.get("entrypoint", "")
    calls = chain.get("calls", [])
    gt_ep = entry.get("entrypoint", {})
    gt_route = gt_ep.get("route", "")
    route_ok = bool(gt_route) and route_matches(gt_route, ep)
    sink_file = cpg_file(record["sink"]["file"])
    if gt_sink and not sink_file.endswith(gt_sink["file"]):
        # forwarding sink on the gt dataflow chain: accept when route matches
        on_chain = any(sink_file.endswith(f) for f in entry.get("chain", []))
        if not (on_chain and route_ok):
            return False
    gt_fn = gt_ep.get("function", "")
    # JSP pages share the generic handler name _jspService — require the
    # route label to discriminate there.
    fn_discriminates = not gt_ep.get("file", "").endswith(".jsp")
    if gt_fn and calls and simple_name(calls[0]) == gt_fn and (fn_discriminates or route_ok):
        return True
    if gt_fn and gt_fn == simple_name(ep):
        return True
    return route_ok


# ---------------------------------------------------------------------------
# Category-B entrypoint matching (M7) — copied from
# scripts/llm_judge_entrypoints.py:247-270 (kept in sync): file+function is
# the primary match (strength 1000), file+route-suffix the fallback, and
# each gt entry keeps only its strongest match so wildcard labels don't
# leak a vulnerable verdict onto a safe sibling.
# ---------------------------------------------------------------------------


def route_specificity(gt_route: str, ep: str) -> int | None:
    """Match a ground-truth route ('GET /users/search') against a hypothesis
    route label (copied from scripts/llm_judge_entrypoints.py). Returns the
    number of matched label segments (higher = more specific), or None.
    Unlike route_matches above, also handles 'GET /users/<id>' raw-path
    labels (the planner's Hypothesis.route shape)."""
    parts = gt_route.split(None, 1)
    if len(parts) != 2:
        return 1 if gt_route.upper() in ep.upper() else None
    method, path = parts[0].upper(), parts[1]
    m = _ep_method(ep)
    if m and m != method:
        return None
    gt_segs = _norm_segs(path)
    cand: list[str] = []
    # quoted fragments (java/csharp annotation style) ...
    for frag in re.findall(r'"([^"]*)"', ep):
        cand.extend(_norm_segs(frag))
    # ... or the raw path after the verb ("GET /users/<id>" style)
    if not cand:
        ep_parts = ep.split(None, 1)
        if len(ep_parts) == 2 and _ep_method(ep_parts[0]):
            cand = _norm_segs(ep_parts[1])
    if not cand:
        return None
    if len(cand) <= len(gt_segs) and gt_segs[-len(cand):] == cand:
        return len(cand)
    return None


def entrypoint_matches_entry(record: dict, entry: dict) -> int:
    """Does this hypothesis record correspond to the ground-truth entry?
    (copied from scripts/llm_judge_entrypoints.py).

    Primary: file + function. Fallback: file + route suffix (needed where
    handlers are anonymous lambdas that never match the gt function name).
    Returns a match STRENGTH (0 = no match); function matches outrank any
    route match, and among route matches the suffix specificity counts."""
    gt_ep = entry.get("entrypoint", {})
    ep = record.get("entrypoint", {})
    gt_file = gt_ep.get("file", "")
    file_ok = bool(gt_file) and cpg_file(ep.get("file", "")).endswith(gt_file)
    gt_fn = gt_ep.get("function", "")
    if gt_fn and file_ok and simple_name(ep.get("method", "")) == gt_fn:
        return 1000
    gt_route = gt_ep.get("route", "")
    if gt_route and (file_ok or not gt_file):
        spec = route_specificity(gt_route, ep.get("route", ""))
        if spec is not None:
            return spec
    return 0


def _hypothesis_as_record(f: dict) -> dict:
    """Adapt a BFinding to the judge's entrypoint-record shape. The
    planner's entrypoint is 'file:function' (or a CPG fullName); the route
    label carries the verb + path."""
    ep = f.get("hypothesis", {}).get("entrypoint", "")
    file, _, fn = ep.partition(":")
    return {"entrypoint": {
        "file": file if fn else "",   # fullName-only labels match by route
        "method": fn or ep,
        "route": f.get("hypothesis", {}).get("route", ""),
    }}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def load_findings(path: str) -> list[dict]:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                rows.append(json.loads(line))
    return rows


def _finding_as_verdicts(f: dict) -> list[dict]:
    """Adapt a Finding to judge-verdicts — one per chain the sink has
    (mirrors the judge's per-chain verdicts; a per-sink Finding otherwise
    matches only its single attached chain). The verdict for the finding's
    SUBMITTED chain is marked primary: it is the chain the agent's verdict
    is actually about."""
    chains = f.get("stats", {}).get("chains") or []
    primary = f.get("chain")

    def as_verdict(c, is_primary: bool) -> dict:
        return {
            "sink": f["sink"],
            # the judge matches on the route LABEL ('GET "/lookup"',
            # 'UserController @GetMapping("/search")') — Chain.route carries
            # it, Chain.entrypoint is the raw CPG fullName
            "entrypoint": (c or {}).get("route") or (c or {}).get("entrypoint", ""),
            # Finding.chain.path is the judge's chain.calls (entrypoint -> sink)
            "calls": (c or {}).get("path", []),
            "status": "JUDGED",
            "is_vulnerable": f["verdict"]["is_vulnerable"],
            "confidence": f["verdict"]["confidence"],
            "primary": is_primary,
        }

    verdicts = []
    primary_in_chains = False
    for c in chains:
        is_primary = primary is not None and json.dumps(c, sort_keys=True) == \
            json.dumps(primary, sort_keys=True)
        primary_in_chains = primary_in_chains or is_primary
        verdicts.append(as_verdict(c, is_primary))
    if primary and not primary_in_chains:
        # agent-submitted chain not in the pipeline list (e.g. drilled)
        verdicts.append(as_verdict(primary, True))
    elif not chains and primary is None:
        pass
    return verdicts


def score_findings(findings: list[dict], ground_truth: list[dict]) -> dict:
    """Same metrics as scripts/llm_judge_sink_chains.py: recall_A, safe
    FPs, TP/FN/FP/TN. A gt entry counts as detected when a matching Finding
    has verdict.is_vulnerable=true."""
    verdicts = [v for f in findings for v in _finding_as_verdicts(f)]
    rows, tp, fn, fp, tn = [], 0, 0, 0, 0
    for entry in ground_truth:
        matches = [
            v for v in verdicts
            if chain_matches_entry({"sink": v["sink"]}, v, entry)
        ]
        # a sink-level "vulnerable" verdict is about the chain the agent
        # submitted; attributing it to a SAFE sample's chain (which the
        # agent may have explicitly identified as sanitized) requires the
        # primary chain to match
        if entry["expected"] == "safe":
            matches = [v for v in matches if v.get("primary")]
        vuln_hits = [m for m in matches if m.get("is_vulnerable")]
        expected = entry["expected"]
        if expected == "vulnerable":
            ok = bool(vuln_hits)
            tp += ok
            fn += not ok
            verdict = "TP" if ok else "FN"
        else:  # safe sample
            bad = bool(vuln_hits)
            fp += bad
            tn += not bad
            verdict = "FP" if bad else "TN"
        rows.append({
            "id": entry["id"], "category": entry["category"],
            "vuln_type": entry.get("vuln_type", ""),
            "expected": expected, "verdict": verdict,
            "findings_matched": len(matches),
            "max_confidence": max((m.get("confidence", 0) for m in vuln_hits), default=0),
        })
    cat_a = [r for r in rows if r["category"] == "A" and r["expected"] == "vulnerable"]
    return {
        "rows": rows,
        "recall_A": _recall(cat_a),
        "recall_A_hit": sum(1 for r in cat_a if r["verdict"] == "TP"),
        "recall_A_total": len(cat_a),
        "safe_fp": [r["id"] for r in rows if r["expected"] == "safe" and r["verdict"] == "FP"],
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
    }


def _recall(rows: list[dict]) -> str:
    if not rows:
        return "n/a"
    hit = sum(1 for r in rows if r["verdict"] == "TP")
    return f"{hit}/{len(rows)} = {hit / len(rows):.0%}"


def score_b_findings(findings: list[dict], ground_truth: list[dict]) -> dict:
    """Category-B metrics (M7), mirroring scripts/llm_judge_entrypoints.py's
    score(): recall_B, safe FP, TP/FN/FP/TN over gt category=="B" entries
    only. A gt entry counts as detected when a best-strength-matching
    BFinding has the same vuln_type and verdict.is_vulnerable=true; a SAFE
    B sample hit by a same-vuln_type vulnerable finding is an FP."""
    records = [(f, _hypothesis_as_record(f)) for f in findings]
    rows, tp, fn, fp, tn = [], 0, 0, 0, 0
    for entry in ground_truth:
        if entry.get("category") != "B":
            continue
        vt = entry.get("vuln_type", "")
        scored = [
            (s, f) for f, rec in records
            if (s := entrypoint_matches_entry(rec, entry)) > 0
        ]
        # keep only the most specific match(es): a wildcard-only label such
        # as 'GET /:id' suffix-matches both 'GET /users/:id' (vulnerable)
        # and 'GET /users/me/:id' (safe) — attributing it to both would
        # turn the vulnerable finding into an FP on the safe sample
        best = max((s for s, _ in scored), default=0)
        matches = [f for s, f in scored if s == best]
        vuln_hits = [
            m for m in matches
            if m.get("hypothesis", {}).get("vuln_type") == vt
            and m.get("verdict", {}).get("is_vulnerable")
        ]
        expected = entry["expected"]
        if expected == "vulnerable":
            ok = bool(vuln_hits)
            tp += ok
            fn += not ok
            verdict = "TP" if ok else "FN"
        else:  # safe sample
            bad = bool(vuln_hits)
            fp += bad
            tn += not bad
            verdict = "FP" if bad else "TN"
        rows.append({
            "id": entry["id"], "category": entry["category"], "vuln_type": vt,
            "expected": expected, "verdict": verdict,
            "findings_matched": len(matches),
            "max_confidence": max(
                (m.get("verdict", {}).get("confidence", 0) for m in vuln_hits),
                default=0),
        })
    vuln_rows = [r for r in rows if r["expected"] == "vulnerable"]
    return {
        "rows": rows,
        "recall_B": _recall(vuln_rows),
        "recall_B_hit": sum(1 for r in vuln_rows if r["verdict"] == "TP"),
        "recall_B_total": len(vuln_rows),
        "safe_fp_b": [r["id"] for r in rows
                      if r["expected"] == "safe" and r["verdict"] == "FP"],
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
    }


# ---------------------------------------------------------------------------
# Validation layer (§6A 校验层 + red line §9.4) — mechanical, no LLM
# ---------------------------------------------------------------------------

import os
from pathlib import Path

# file refs are extracted, not full-matched: agents legitimately append
# prose ("Controllers/X.cs:11-22 (entrypoint X.Parse)") — the checkable
# part is the file:start-end prefix. Refs without any file:line token
# (e.g. a CPG method fullName) are uncheckable and skipped, not flagged.
_REF_RE = re.compile(
    r"([\w./-]+\.(?:py|js|ts|java|cs|jsp)):(\d+)(?:-(\d+))?")
# a "code identifier" token: snake_case / camelCase / CONSTANT — plain
# English words don't count toward the identifier check
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_GROUND_TRUTH_NAMES = {"ground_truth.json", "GROUND_TRUTH.md"}

# All-caps tokens that are prose, not code identifiers: HTTP methods,
# protocol/format acronyms and pipeline status words. Without this filter
# the identifier check fired on "GET /search ..." style summaries (false
# "evidence gap" on the 2026-08-12 M3 runs).
_IDENT_STOPWORDS = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
    "HTTP", "HTTPS", "SQL", "HTML", "XML", "XSS", "JSON", "URL", "URI",
    "API", "CSS", "DTD", "CWE", "TCP", "TLS", "SSL", "UTF", "CLI",
    "CONFIRMED", "UNCONFIRMED", "LIKELY", "SUSPICIOUS",
}


def _code_identifiers(text: str) -> list[str]:
    out = []
    for tok in _IDENT_RE.findall(text):
        if tok in _IDENT_STOPWORDS:
            continue
        if len(tok) >= 3 and ("_" in tok or re.search(r"[a-z][A-Z]", tok)
                              or tok.isupper()):
            out.append(tok)
    return out


def validate_finding(f: dict, tree: Path) -> list[str]:
    """Mechanically check a finding's evidence against the target tree.
    Returns a list of violation strings (empty = clean).

    Checks (§6A 校验层):
    - every evidence ref "file:start-end" resolves under the tree
      (ground-truth files excluded), the slice exists and is non-blank;
    - if the evidence summary cites code identifiers, at least one must
      appear in the union of the entry's referenced slices;
    - for drilled (multi-file) paths, every evidence file must be backed
      by a tool_log entry (read/search/query/snippets) that touched it;
    - red line §9.4: CONFIRMED requires an exploit_sketch and refs.
    """
    violations: list[str] = []
    tree = tree.resolve()
    evidence = f.get("evidence", [])
    ref_files: set[str] = set()
    n_file_refs = 0  # only file:line refs count toward the §9.4 requirement

    for e in evidence:
        summary = e.get("summary", "")
        # The identifier check applies only to code_read entries — the ones
        # claiming "I read this code". chain/taint_flow/joern_query summaries
        # legitimately cite engine facts (FromBody attributes, method
        # fullNames, CONFIRMED flags) that need not appear in the refs.
        idents = _code_identifiers(summary) if e.get("kind") == "code_read" else []
        entry_slices: list[str] = []
        for ref in e.get("refs", []):
            m = _REF_RE.search(ref.strip())
            if not m:
                continue  # uncheckable ref (method fullName, prose) — skipped
            n_file_refs += 1
            rel, start, end = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
            ref_files.add(rel)
            if os.path.basename(rel) in _GROUND_TRUTH_NAMES:
                violations.append(f"evidence ref {ref!r} points at ground truth")
                continue
            path = (tree / rel).resolve()
            if tree not in path.parents and path != tree:
                violations.append(f"evidence ref {ref!r} escapes the target tree")
                continue
            if not path.is_file():
                violations.append(f"evidence ref {ref!r}: file not found")
                continue
            lines = path.read_text(errors="replace").splitlines()
            if start < 1 or end > len(lines) or start > end:
                violations.append(f"evidence ref {ref!r}: out of range "
                                  f"({rel} has {len(lines)} lines)")
                continue
            slice_text = "\n".join(lines[start - 1:end])
            if not slice_text.strip():
                violations.append(f"evidence ref {ref!r}: empty line range")
                continue
            entry_slices.append(slice_text)
        # Identifier check is per ENTRY, against the union of its refs'
        # slices: agents legitimately cite single lines (e.g. just the sink
        # call) while the identifiers they mention live on adjacent cited
        # lines. Per-ref checking downgraded correct findings (false
        # "evidence gap" on the 2026-08-11 M3 runs).
        if idents and entry_slices:
            union = "\n".join(entry_slices)
            if not any(i in union for i in idents):
                violations.append(
                    f"evidence entry ({summary[:60]!r}): none of the cited "
                    f"identifiers {idents[:5]} appear in the referenced slices")

    # drilled-path support: multi-file evidence must be backed by tool calls
    tool_log = f.get("stats", {}).get("tool_log", [])
    if len(ref_files) > 1:
        if not tool_log:
            violations.append("multi-file evidence path but no tool_log recorded")
        else:
            logged = "\n".join(
                f"{entry['tool']} {json.dumps(entry.get('args', {}))} "
                f"{' '.join(entry.get('refs', []))}" for entry in tool_log)
            for rel in sorted(ref_files):
                base = os.path.basename(rel)
                if rel not in logged and base not in logged:
                    violations.append(
                        f"evidence file {rel!r} has no supporting tool call "
                        f"(segment jump not backed by a tool result)")

    # red line §9.4: CONFIRMED needs an exploit sketch and checkable refs
    if f.get("confidence_level") == "CONFIRMED":
        if not f.get("exploit_sketch"):
            violations.append("CONFIRMED without an exploit_sketch")
        if not n_file_refs:
            violations.append("CONFIRMED without any file:line evidence ref")

    return violations


def apply_validation(findings: list[dict], tree: Path,
                     b_class: bool = False) -> list[dict]:
    """Downgrade CONFIRMED findings with validation violations to LIKELY and
    attach the violation list (§6A 校验层: 造假或断档 -> 自动降级).

    b_class=True adds the M7 category-B rule (plan §4): a CONFIRMED B
    finding must carry absence_comparison evidence (the missing spot + the
    comparison route's check location), else it drops to LIKELY."""
    for f in findings:
        violations = validate_finding(f, tree)
        f["validation"] = {"violations": violations}
        if f.get("confidence_level") == "CONFIRMED":
            if b_class and not any(
                    e.get("kind") == "absence_comparison"
                    for e in f.get("evidence", [])):
                violations.append("CONFIRMED without absence_comparison "
                                  "evidence (category-B rule)")
                f["validation"]["violations"] = violations
            if violations:
                f["confidence_level"] = "LIKELY"
                f["validation"]["downgraded"] = (
                    "evidence gap: " + "; ".join(violations[:3]))
    return findings


# ---------------------------------------------------------------------------
# M4 adversarial-review merge (plan §7 -> §4 mapping) — mechanical, no LLM
# ---------------------------------------------------------------------------

def _refs_resolve(refs: list[str], tree: Path) -> bool:
    """At least one "file:start-end" ref resolves to real lines under the
    tree. A defender veto is honored only with concrete, checkable code —
    an unverifiable sanitizer claim must never hide a real vulnerability."""
    tree = tree.resolve()
    for ref in refs:
        m = _REF_RE.search(ref.strip())
        if not m:
            continue
        rel, start, end = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
        if os.path.basename(rel) in _GROUND_TRUTH_NAMES:
            continue
        path = (tree / rel).resolve()
        if tree not in path.parents and path != tree:
            continue
        if path.is_file():
            lines = path.read_text(errors="replace").splitlines()
            if 1 <= start <= end <= len(lines):
                return True
    return False


def apply_verifier(finding: dict, verifier: dict,
                   tree: Path | None = None) -> dict:
    """Merge the M4 attacker/defender rounds into verdict + confidence_level
    (plan §7, mapping per §4). Mechanical — the LLM rounds only supply the
    attacker/defender reports; every consequence is decided here:

    - not-vulnerable findings: verifier skipped (it only runs on vulnerable
      verdicts; if the verdict is already False there is nothing to attack);
    - defender veto: effective_sanitizer=true AND at least one cited ref
      resolves under the tree -> verdict flips to not vulnerable, level
      SUSPICIOUS, reasoning annotated. Unverifiable sanitizer claims are
      ignored (noted in stats.verifier.notes);
    - attacker failure: exploit_possible=false -> downgrade one level
      (CONFIRMED -> LIKELY -> SUSPICIOUS);
    - side effect: empty exploit_sketch / sanitizer_notes are filled from
      the verifier reports (§9.4 wants an exploit sketch on CONFIRMED);
    - a failed round (None report: timeout/quota) has no effect.
    """
    v = finding["verdict"]
    if not v.get("is_vulnerable"):
        finding.setdefault("stats", {})["verifier"] = {
            "skipped": "not vulnerable", "tokens": verifier.get("tokens", 0)}
        return finding

    att = verifier.get("attacker") or {}
    dfn = verifier.get("defender") or {}
    notes: list[str] = []
    level = finding.get("confidence_level", "LIKELY")
    veto = False

    if dfn.get("effective_sanitizer"):
        refs_ok = (_refs_resolve(dfn.get("refs", []), tree) if tree
                   else bool(dfn.get("refs")))
        if refs_ok:
            veto = True
        else:
            notes.append("defender claimed a sanitizer but cited no "
                         "resolvable refs — claim ignored")

    if veto:
        v["is_vulnerable"] = False
        v["confidence"] = min(v.get("confidence", 0.5), 0.4)
        v["reasoning"] = (
            v.get("reasoning", "")
            + f" [Verifier veto: defender found an effective sanitizer "
              f"({dfn.get('kind') or 'see refs'}) at "
              f"{', '.join(dfn.get('refs', [])[:3])}: "
              f"{(dfn.get('reasoning') or '')[:200]}]")
        level = "SUSPICIOUS"
    else:
        if att and not att.get("exploit_possible"):
            level = {"CONFIRMED": "LIKELY", "LIKELY": "SUSPICIOUS"}.get(level, level)
            notes.append("attacker could not construct a trigger request — "
                         "downgraded one level")
        if att.get("request") and not finding.get("exploit_sketch"):
            finding["exploit_sketch"] = att["request"]
        if dfn.get("reasoning") and not finding.get("sanitizer_notes"):
            kind = f" ({dfn['kind']})" if dfn.get("kind") else ""
            finding["sanitizer_notes"] = f"[defender{kind}] {dfn['reasoning']}"

    finding["confidence_level"] = level
    finding.setdefault("stats", {})["verifier"] = {
        "attacker": att or None,
        "defender": dfn or None,
        "tokens": verifier.get("tokens", 0),
        "status": verifier.get("status", {}),
        "veto": veto,
        "notes": notes,
    }
    return finding


def apply_verifier_b(finding: dict, verifier: dict,
                     tree: Path | None = None) -> dict:
    """M7 category-B merge — thin wrapper over apply_verifier. The merge is
    generic dict surgery on verdict/confidence_level/exploit_sketch/
    sanitizer_notes (nothing sink-specific), and BFindings carry all four.
    The defender veto still requires >=1 cited ref resolving on disk, so a
    hallucinated middleware guard can never hide a real vulnerability."""
    return apply_verifier(finding, verifier, tree)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def render_markdown(findings: list[dict], score: dict | None = None) -> str:
    lines = ["# SAST Agent Report", ""]
    if score:
        lines += [
            f"- Recall category A: **{score['recall_A']}**",
            f"- Safe-sample false positives: {score['safe_fp'] or 'none'}",
            f"- TP={score['tp']} FN={score['fn']} FP={score['fp']} TN={score['tn']}",
        ]
    levels: dict[str, int] = {}
    for f in findings:
        levels[f["confidence_level"]] = levels.get(f["confidence_level"], 0) + 1
    lines.append(
        "- Confidence levels: "
        + ", ".join(f"{lvl} {levels.get(lvl, 0)}"
                    for lvl in ("CONFIRMED", "LIKELY", "SUSPICIOUS")))
    lines.append("")
    for f in findings:
        sink, verdict = f["sink"], f["verdict"]
        chain = f.get("chain") or {}
        route = chain.get("route") or chain.get("entrypoint") or "(no chain)"
        stats = f.get("stats", {})
        lines += [
            f"## {sink['id']}",
            "",
            f"- Sink: `{sink['name']}` at {sink['file']}:{sink['line']} "
            f"({sink['vuln_type']}, rule {sink['rule']})",
            f"- Route: {route}",
            f"- Verdict: **{'VULNERABLE' if verdict['is_vulnerable'] else 'not vulnerable'}** "
            f"({f['confidence_level']}, confidence {verdict['confidence']:.2f})",
            f"- Reasoning: {verdict['reasoning']}",
        ]
        refs = [ref for e in f.get("evidence", []) for ref in e.get("refs", [])]
        if refs:
            lines.append(f"- Evidence refs: {', '.join(refs)}")
        if f.get("exploit_sketch"):
            lines.append(f"- Exploit sketch: {f['exploit_sketch']}")
        if f.get("sanitizer_notes"):
            lines.append(f"- Sanitizer notes: {f['sanitizer_notes']}")
        lines.append(
            f"- Stats: {stats.get('tool_calls', '?')} tool calls, "
            f"{stats.get('tokens', '?')} tokens, {stats.get('seconds', '?')}s "
            f"({stats.get('status', '?')})")
        vf = stats.get("verifier") or {}
        if vf.get("skipped"):
            pass  # verifier only runs on vulnerable verdicts
        elif "attacker" in vf or "defender" in vf:
            att, dfn = vf.get("attacker") or {}, vf.get("defender") or {}
            line = ("- Verifier: attacker exploit="
                    + ("yes" if att.get("exploit_possible") else "no")
                    + "; defender sanitizer="
                    + ("yes" if dfn.get("effective_sanitizer") else "no")
                    + (f" ({dfn['kind']})" if dfn.get("effective_sanitizer")
                       and dfn.get("kind") else ""))
            if vf.get("veto"):
                line += " — VETOED to not vulnerable"
            for note in vf.get("notes", []):
                line += f"; {note}"
            lines.append(line)
        val = f.get("validation") or {}
        if val.get("downgraded"):
            lines.append(f"- Validation: downgraded to LIKELY — {val['downgraded']}")
        elif val.get("violations"):
            lines.append(f"- Validation: {'; '.join(val['violations'][:3])}")
        lines.append("")
    return "\n".join(lines)


def render_markdown_b(findings: list[dict], score: dict | None = None,
                      checklist: dict | None = None) -> str:
    """Category-B report (M7): hypothesis-shaped sections — no sink —
    with the absence-comparison evidence block and the Verifier line.
    `checklist` (M8) is the planner's taxonomy coverage checklist, rendered
    as a trailing audit section (§7A 完整性约束)."""
    lines = ["# SAST Agent Report — Category B (M7)", ""]
    if score:
        lines += [
            f"- Recall category B: **{score['recall_B']}**",
            f"- Safe-sample false positives (B): {score['safe_fp_b'] or 'none'}",
            f"- TP={score['tp']} FN={score['fn']} FP={score['fp']} TN={score['tn']}",
        ]
    levels: dict[str, int] = {}
    for f in findings:
        levels[f["confidence_level"]] = levels.get(f["confidence_level"], 0) + 1
    lines.append(
        "- Confidence levels: "
        + ", ".join(f"{lvl} {levels.get(lvl, 0)}"
                    for lvl in ("CONFIRMED", "LIKELY", "SUSPICIOUS")))
    lines.append("")
    for f in findings:
        hyp, verdict = f["hypothesis"], f["verdict"]
        stats = f.get("stats", {})
        lines += [
            f"## {hyp['vuln_type']}: {hyp['route']}",
            "",
            f"- Entrypoint: `{hyp['entrypoint']}`",
            f"- Trigger features: {hyp.get('trigger_features', '')}",
            f"- Planner rationale: {hyp.get('rationale', '')}",
            f"- Verdict: **{'VULNERABLE' if verdict['is_vulnerable'] else 'not vulnerable'}** "
            f"({f['confidence_level']}, confidence {verdict['confidence']:.2f})",
            f"- Reasoning: {verdict['reasoning']}",
        ]
        absence = [e for e in f.get("evidence", [])
                   if e.get("kind") == "absence_comparison"]
        if absence or f.get("comparison"):
            lines.append("- Absence comparison:")
            if f.get("comparison"):
                lines.append(f"  - Comparison: {f['comparison']}")
            for e in absence:
                lines.append(
                    f"  - {e.get('summary', '')} "
                    f"(refs: {', '.join(e.get('refs', [])) or 'none'})")
        refs = [ref for e in f.get("evidence", []) for ref in e.get("refs", [])]
        if refs:
            lines.append(f"- Evidence refs: {', '.join(refs)}")
        if f.get("exploit_sketch"):
            lines.append(f"- Exploit sketch: {f['exploit_sketch']}")
        if f.get("sanitizer_notes"):
            lines.append(f"- Sanitizer notes: {f['sanitizer_notes']}")
        lines.append(
            f"- Stats: {stats.get('tool_calls', '?')} tool calls, "
            f"{stats.get('tokens', '?')} tokens, {stats.get('seconds', '?')}s "
            f"({stats.get('status', '?')})")
        vf = stats.get("verifier") or {}
        if vf.get("skipped"):
            pass  # verifier only runs on vulnerable verdicts
        elif "attacker" in vf or "defender" in vf:
            att, dfn = vf.get("attacker") or {}, vf.get("defender") or {}
            line = ("- Verifier: attacker exploit="
                    + ("yes" if att.get("exploit_possible") else "no")
                    + "; defender guard="
                    + ("yes" if dfn.get("effective_sanitizer") else "no")
                    + (f" ({dfn['kind']})" if dfn.get("effective_sanitizer")
                       and dfn.get("kind") else ""))
            if vf.get("veto"):
                line += " — VETOED to not vulnerable"
            for note in vf.get("notes", []):
                line += f"; {note}"
            lines.append(line)
        val = f.get("validation") or {}
        if val.get("downgraded"):
            lines.append(f"- Validation: downgraded to LIKELY — {val['downgraded']}")
        elif val.get("violations"):
            lines.append(f"- Validation: {'; '.join(val['violations'][:3])}")
        lines.append("")
    lines += _render_checklist_section(checklist)
    return "\n".join(lines)


def _render_checklist_section(checklist: dict | None) -> list[str]:
    """M8 taxonomy coverage audit section (§7A 完整性约束): per class, how
    many routes the planner examined, submitted, and excluded (with the
    exclusion reasons — the recall guarantee when no ground truth exists)."""
    lines = ["## Taxonomy coverage audit", ""]
    if checklist is None:
        lines.append("Not available (hypothesis queue predates the M8 "
                     "planner checklist — re-run run_planner.py).")
        return lines
    if checklist.get("derived"):
        lines.append("> Warning: planner's checklist was incomplete; missing "
                     "classes were auto-filled from the queue (routes_examined "
                     "= 0 means \"not reported\").")
        lines.append("")
    lines.append("| class | examined | submitted | excluded (route — reason) |")
    lines.append("|---|---|---|---|")
    for e in checklist.get("entries", []):
        excluded = "; ".join(f"{x['route']} — {x['reason']}"
                             for x in e.get("excluded", [])) or "—"
        lines.append(f"| {e['vuln_type']} | {e['routes_examined']} "
                     f"| {len(e.get('submitted', []))} | {excluded} |")
    return lines


def summary_text_b(score: dict) -> str:
    """Category-B printable summary (same table shape as summary_text)."""
    out = [f"\n{'id':<28} {'cat':<3} {'vuln_type':<17} {'expected':<10} verdict"]
    for r in score["rows"]:
        out.append(f"{r['id']:<28} {r['category']:<3} {r['vuln_type']:<17} "
                   f"{r['expected']:<10} {r['verdict']}")
    out += [
        f"\nRecall category B (non-sink):    {score['recall_B']}",
        f"Safe-sample false positives (B): {score['safe_fp_b'] or 'none'}",
        f"TP={score['tp']} FN={score['fn']} FP={score['fp']} TN={score['tn']}",
    ]
    return "\n".join(out)


def summary_text(score: dict) -> str:
    """Judge-style printable summary."""
    out = [f"\n{'id':<28} {'cat':<3} {'vuln_type':<17} {'expected':<10} verdict"]
    for r in score["rows"]:
        out.append(f"{r['id']:<28} {r['category']:<3} {r['vuln_type']:<17} "
                   f"{r['expected']:<10} {r['verdict']}")
    out += [
        f"\nRecall category A (sink-based):  {score['recall_A']}",
        f"Safe-sample false positives:     {score['safe_fp'] or 'none'}",
        f"TP={score['tp']} FN={score['fn']} FP={score['fp']} TN={score['tn']}",
    ]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--findings", required=True, help="findings JSONL")
    ap.add_argument("--ground-truth", required=True, help="target's ground_truth.json")
    ap.add_argument("--tree", default="",
                    help="target source tree (enables the §6A validation layer)")
    ap.add_argument("-o", "--output", default="-", help="report.md (default: stdout)")
    args = ap.parse_args()

    findings = load_findings(args.findings)
    if args.tree:
        findings = apply_validation(findings, Path(args.tree))
    with open(args.ground_truth) as f:
        ground_truth = json.load(f)
    score = score_findings(findings, ground_truth)
    md = render_markdown(findings, score)
    if args.output != "-":
        with open(args.output, "w") as f:
            f.write(md + "\n")
        sys.stderr.write(f"// report written to {args.output}\n")
    print(summary_text(score))
    return 0


if __name__ == "__main__":
    sys.exit(main())
