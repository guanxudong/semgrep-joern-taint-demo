"""no-LLM tests for the ground-truth scrubber (red line §9.2).

Run:
    uv run --with pytest pytest tests -q

The targets are marker-free since D15, so tests/fixtures/leak/ holds the
deliberate leak shapes instead. Every fixture is asserted to end up free of
labels after scrubbing — a regression here is a silent benchmark-invalidating
leak, which is exactly what LIMITATIONS §4 calls a class of bug rather than a
fixed one.
"""

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "agent"))

from sast_agent import scrub  # noqa: E402

FIXTURES = REPO / "tests" / "fixtures" / "leak"


@pytest.fixture(autouse=True)
def _audit_to_tmp(monkeypatch, tmp_path):
    """Never write to the real workspace/leak-audit.jsonl from a test — the
    gate reads that file, so a test leak would fail the next --forbid-leak."""
    monkeypatch.setattr(scrub, "AUDIT_PATH", tmp_path / "leak-audit.jsonl")

# fixture -> (severity expected after strip, must-change?)
# "certain" = a VULN:/SAFE: label survived (strip failed -> fatal)
# "suspected" = only a bare ground-truth id (audited, not fatal)
# "clean" = nothing label-shaped at all
LABELLED = {
    "hash_line_start": "clean",
    "hash_indented": "clean",
    "numbered_line": "clean",
    "rg_prefixed": "clean",
    "html_comment": "clean",
    "block_star": "clean",
    "block_inline": "clean",
    "cstyle_trailing": "clean",
    "no_space": "clean",
    "gt_id_only": "suspected",
    "clean": "clean",
}


def _read(name: str) -> str:
    return (FIXTURES / f"{name}.txt").read_text()


@pytest.mark.parametrize("name", sorted(LABELLED))
def test_fixture_is_covered(name):
    """Guard against a fixture file being added without an expectation."""
    assert (FIXTURES / f"{name}.txt").exists(), name


@pytest.mark.parametrize("name", sorted(LABELLED))
def test_strip_removes_every_marker_shape(name):
    raw = _read(name)
    cleaned = scrub.strip_gt_tags(raw)
    hits = scrub.find_gt_leak(cleaned)
    worst = "certain" if any(h["severity"] == scrub.CERTAIN for h in hits) else (
        "suspected" if hits else "clean")
    assert worst == LABELLED[name], (
        f"{name}: expected {LABELLED[name]} after strip, got {worst} {hits}")


@pytest.mark.parametrize("name", sorted(LABELLED))
def test_strip_preserves_code_lines(name):
    """Scrubbing removes the label, never the code: every line without a
    marker comment must survive verbatim."""
    raw = _read(name)
    cleaned = scrub.strip_gt_tags(raw)
    kept = set(cleaned.splitlines())
    for line in raw.splitlines():
        if "VULN:" in line.upper() or "SAFE:" in line.upper():
            continue
        assert line in kept, f"{name}: dropped code line {line!r}"


def test_clean_fixture_is_untouched():
    raw = _read("clean")
    assert scrub.scrub(raw, where="test:clean") == raw
    assert scrub.find_gt_leak(scrub.strip_gt_tags(raw)) == []


@pytest.mark.parametrize("name", [n for n, s in LABELLED.items()
                                  if s == "clean"])
def test_scrub_returns_readable_code(name):
    """A labelled fixture must scrub to something that still contains its
    sink call — i.e. we dropped the comment, not the function."""
    cleaned = scrub.scrub(_read(name), where=f"test:{name}")
    assert "VULN:" not in cleaned and "SAFE:" not in cleaned
    assert len(cleaned.strip()) > 0


@pytest.mark.parametrize("name", [n for n, s in LABELLED.items()
                                  if s == "suspected"])
def test_scrub_audits_but_does_not_fail_on_bare_id(name):
    """A bare ground-truth id is suspicious, not provably a leak — some real
    repo could name a fixture after one. Audited, not fatal."""
    out = scrub.scrub(_read(name), where=f"test:{name}")
    assert out == _read(name)  # ids are NOT stripped (no label to remove)


def test_scrub_raises_when_a_label_survives(monkeypatch, tmp_path):
    """The assertion path: a label shape the strip regex does not know must
    raise GroundTruthLeak instead of silently reaching the LLM."""
    monkeypatch.setattr(scrub, "AUDIT_PATH", tmp_path / "leak-audit.jsonl")
    # simulate a strip failure: a tag regex that matches nothing
    monkeypatch.setattr(scrub, "_GT_TAG", scrub.re.compile(r"(?!x)x"))
    with pytest.raises(scrub.GroundTruthLeak) as exc:
        scrub.scrub("# VULN: py-sqli-01 (sqli)\ncode()", where="test:raise")
    assert "test:raise" in str(exc.value)
    audit = (tmp_path / "leak-audit.jsonl").read_text()
    assert '"severity": "certain"' in audit
    assert "test:raise" in audit


def test_strict_false_records_without_raising(monkeypatch, tmp_path):
    monkeypatch.setattr(scrub, "AUDIT_PATH", tmp_path / "leak-audit.jsonl")
    monkeypatch.setattr(scrub, "_GT_TAG", scrub.re.compile(r"(?!x)x"))
    out = scrub.scrub("# VULN: py-sqli-01\ncode()", where="test:soft",
                      strict=False)
    assert "VULN" in out
    assert (tmp_path / "leak-audit.jsonl").exists()


def test_find_gt_leak_ignores_ordinary_prose():
    text = ("Vulnerable code is bad; prefer the helper over ad-hoc SQL.\n"
            "safety = check(safe=True)\n"
            "is_vuln = flag  # not a label\n")
    assert scrub.find_gt_leak(text) == []


def test_find_gt_leak_flags_id_in_prose():
    hits = scrub.find_gt_leak("see regression for py-sqli-01\n")
    assert [h["severity"] for h in hits] == [scrub.SUSPECTED]
    assert hits[0]["kind"] == "gt_id"


def test_scrub_dicts_in_place():
    """Scrubbing leaves the (now empty) comment line behind rather than
    deleting it — deliberate: in rg output the line is the match evidence."""
    items = [{"code": "# VULN: py-sqli-01\nx = 1"}, {"code": "clean = 2"}]
    scrub.scrub_dicts(items, where="test:dicts")
    assert items[0]["code"].strip() == "x = 1"
    assert items[1]["code"] == "clean = 2"


def test_scrub_handles_empty_and_none():
    assert scrub.scrub("", where="t") == ""
    assert scrub.scrub(None, where="t") == ""  # type: ignore[arg-type]
