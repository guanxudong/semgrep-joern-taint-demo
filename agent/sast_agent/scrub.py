"""Ground-truth label scrubbing + leak assertion (red line §9.2).

SINGLE implementation, shared by the agent tool layer (`tools.py`,
`investigator.py`, `worker.py`, `verifier.py`) and both LLM judges
(`scripts/llm_judge_sink_chains.py`, `scripts/llm_judge_entrypoints.py`).
Before this module the same regex existed in four divergent copies: the
agent copies dropped the tag anywhere on a line (read_function prefixes
lines with `  12: `, search_code returns `path:12:content`) while the
judge copies were `^`-anchored — the drift that let a labelled rg line
through once already (M7 acceptance).

Two responsibilities:

1. `strip_gt_tags(code)` — remove marker comments (`// VULN: id`,
   `# SAFE: id`, `<!-- VULN: id -->`, `* VULN: id`, `/* VULN: id */`).
2. `scrub(text, where=...)` — strip, then ASSERT nothing label-shaped
   survived, append any finding to `workspace/leak-audit.jsonl` and raise
   `GroundTruthLeak` on a certain hit. Stripping silently is what made the
   M7 leak invisible; a scrub that fails must be loud.

Severity model: a surviving `VULN:`/`SAFE:` label is *certain* (the strip
regex covers every known form, so a survivor means the input shape is new
— exactly the M7 failure mode). A bare ground-truth id literal
(`py-sqli-01`) is *suspected*: it is a strong signal, but a project could
legitimately name a fixture after one, so it is audited, not fatal.

The id pattern is a hardcoded shape, NOT read from ground_truth.json —
the agent tool layer must never touch the ground-truth files (red line
§9.2), so this module stays dependency-free and ground-truth-blind.
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
AUDIT_PATH = REPO / "workspace" / "leak-audit.jsonl"

# Marker comment: any comment opener, then VULN:/SAFE:, then the rest of
# the line. Not anchored — tool output prefixes lines (read_function line
# numbers, rg's path:line:).
_GT_TAG = re.compile(
    r"(?://|#|/\*|<!--|\*)\s*(?:VULN|SAFE)\s*:[^\n]*", re.IGNORECASE)

# Marker word with no comment opener, e.g. prose or an HTML/JSP comment
# variant we do not enumerate: `VULN: py-sqli-01`.
_GT_WORD = re.compile(r"\b(?:VULN|SAFE)\s*:\s*[a-z0-9]+-", re.IGNORECASE)

# Ground-truth id literal shape: <lang>-<vuln_type>[-safe]-<nn>.
_GT_ID = re.compile(
    r"\b(?:py|java|js|cs|php|pl|jsp|ts|kt|rb|go)-"
    r"(?:sqli|xss|cmdi|cmd-injection|path-traversal|path|rce|xxe|"
    r"deserialization|ssti|idor|business-logic|race-condition|priv-esc|"
    r"privilege-escalation|mass-assignment|broken-access-control|auth-flaws|"
    r"auth|safe)"
    r"-(?:safe-)?\d+\b", re.IGNORECASE)

CERTAIN = "certain"
SUSPECTED = "suspected"


class GroundTruthLeak(RuntimeError):
    """A ground-truth label survived scrubbing and would reach an LLM."""


def strip_gt_tags(code: str) -> str:
    """Remove ground-truth marker comments from `code`."""
    if not code:
        return code
    return _GT_TAG.sub("", code)


def find_gt_leak(text: str) -> list[dict]:
    """Label-shaped survivors in `text` (call AFTER strip_gt_tags).

    Returns [{"severity", "kind", "excerpt"}, ...] — empty when clean.
    """
    if not text:
        return []
    hits: list[dict] = []
    for kind, rx in (("marker_label", _GT_WORD), ("gt_id", _GT_ID)):
        for m in rx.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            line = text[line_start:line_end if line_end != -1 else len(text)]
            hits.append({
                "severity": CERTAIN if kind == "marker_label" else SUSPECTED,
                "kind": kind,
                "match": m.group(0),
                "excerpt": line.strip()[:200],
            })
    return hits


def _audit(entries: list[dict], where: str, target: str | None) -> None:
    """Append leak findings to workspace/leak-audit.jsonl (best effort)."""
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_PATH, "a") as fh:
            for e in entries:
                fh.write(json.dumps({
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    # epoch seconds as well: the regression gate scopes leaks
                    # to "recorded after this run's summary", and string
                    # timestamps would lose sub-second ordering
                    "ts_epoch": round(time.time(), 3),
                    "where": where,
                    "target": target,
                    **e,
                }, ensure_ascii=False) + "\n")
    except OSError:
        pass


_audit_lock = threading.Lock()


def scrub(text: str, *, where: str, target: str | None = None,
          strict: bool = True) -> str:
    """Strip ground-truth labels, then assert none survived.

    `where` names the call site (e.g. "tools.read_function:routes.py") and
    lands in the audit record. Raises GroundTruthLeak on a certain hit
    unless `strict=False` (used by the leak-detector's own self-test).
    """
    cleaned = strip_gt_tags(text or "")
    hits = find_gt_leak(cleaned)
    if hits:
        with _audit_lock:
            _audit(hits, where, target)
    certain = [h for h in hits if h["severity"] == CERTAIN]
    if certain and strict:
        raise GroundTruthLeak(
            f"ground-truth label survived scrub at {where}: "
            + "; ".join(sorted({h['match'] for h in certain})[:5])
            + f" (audit: {AUDIT_PATH})")
    return cleaned


def scrub_dicts(items: list, code_key: str = "code", *, where: str,
                target: str | None = None) -> list:
    """Scrub the `code_key` field of every dict in `items` (in place)."""
    for i, d in enumerate(items or []):
        if isinstance(d, dict) and d.get(code_key):
            d[code_key] = scrub(d[code_key], where=f"{where}[{i}]",
                                target=target)
    return items
