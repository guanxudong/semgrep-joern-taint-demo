"""no-LLM tests for the regression gate (agent/run_baseline.py --compare).

Covers the three dimensions added on top of the M5/M8 recall/FP gate:
SKIP-vs-FAIL semantics for targets without a comparable baseline (P0),
provenance classification of a failure (P2), and the token / confirmed-rate /
leak dimensions (P3).

Run:
    uv run --with pytest pytest tests -q
"""

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load_run_baseline():
    """Import agent/run_baseline.py as a module (it is a script, not a package
    member, and its module-level code is stdlib-only)."""
    spec = importlib.util.spec_from_file_location(
        "run_baseline_under_test", REPO / "agent" / "run_baseline.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rb = _load_run_baseline()


def _judge(recall="10/10", fp=None):
    return {"recall": recall, "safe_fp": fp or [], "tp": 10, "fn": 0,
            "fp": 0, "tn": 5, "llm_errors": 0}


def _write_baseline(tmp_path, targets, prov=None):
    base = {"version": 2, "provenance": prov or {}, "targets": targets}
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps(base, indent=2))
    return p


def _write_summary(tmp_path, targets, name="summary.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"targets": targets}, indent=2))
    return p


@pytest.fixture
def gate(tmp_path, monkeypatch, capsys):
    """Wire the gate onto a temp baseline / report dir."""
    monkeypatch.setattr(rb, "BASELINE_FILE", tmp_path / "baseline.json")
    (tmp_path / "cache").mkdir()  # the gate reads per-target artifact hashes
    # from workspace/agent-cache/<target>/ when that dir exists
    monkeypatch.setattr(rb, "AGENT_CACHE", tmp_path / "cache")
    monkeypatch.setattr(rb, "REPORT_ROOT", tmp_path / "reports")
    monkeypatch.setattr(rb, "LEAK_AUDIT", tmp_path / "leak-audit.jsonl")

    def run(summary_targets, baseline_targets, prov=None, **kwargs):
        _write_baseline(tmp_path, baseline_targets, prov)
        summary = _write_summary(tmp_path, summary_targets)
        code = rb.compare_with_baseline(summary, **kwargs)
        return code, capsys.readouterr().out

    return run


# ---- P0: SKIP is not a regression ---------------------------------------

def test_target_without_judge_baseline_is_skipped_not_failed(gate):
    """python-flask-enterprise was frozen with --skip-llm, so judge_a is
    empty. Before this fix the gate FAILED unconditionally on it, which made
    every `--target all` run exit 1 for reasons unrelated to code quality."""
    code, out = gate(
        summary_targets={"python-flask-enterprise": {"recall_A_hit": 12,
                                                     "recall_A": "12/12",
                                                     "safe_fp": [], "tokens": 1}},
        baseline_targets={"python-flask-enterprise": {"chains": {}, "judge_a": {},
                                                      "judge_b": {}}})
    assert code == 0
    assert "SKIP" in out and "no judge_a baseline" in out


def test_require_baseline_promotes_skip_to_fail(gate):
    code, out = gate(
        summary_targets={"python-flask-enterprise": {"recall_A_hit": 12,
                                                     "recall_A": "12/12",
                                                     "safe_fp": []}},
        baseline_targets={"python-flask-enterprise": {"judge_a": {}, "judge_b": {}}},
        require_baseline=True)
    assert code == 1
    assert "FAIL" in out


def test_missing_baseline_entry_fails(gate):
    code, out = gate(summary_targets={"python-flask": {"recall_A_hit": 10}},
                     baseline_targets={})
    assert code == 1
    assert "no baseline entry" in out


# ---- original M5/M8 dimensions still hold --------------------------------

def test_equal_recall_passes(gate):
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                                          "safe_fp": [], "tokens": 1000}},
        baseline_targets={"python-flask": {"judge_a": _judge(), "judge_b": {}}})
    assert code == 0 and "PASS" in out


def test_recall_drop_fails(gate):
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 9, "recall_A": "9/10",
                                          "safe_fp": []}},
        baseline_targets={"python-flask": {"judge_a": _judge(), "judge_b": {}}})
    assert code == 1
    assert "recall dropped 10 -> 9" in out


def test_baseline_known_fp_tolerated_new_fp_fails(gate):
    known = {"python-flask": {"judge_a": _judge(fp=["py-safe-02"]), "judge_b": {}}}
    code, _ = gate(
        summary_targets={"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                                          "safe_fp": ["py-safe-02"]}},
        baseline_targets=known)
    assert code == 0
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                                          "safe_fp": ["py-safe-02", "py-safe-04"]}},
        baseline_targets=known)
    assert code == 1
    assert "new safe FP" in out


def test_run_error_fails(gate):
    code, out = gate(summary_targets={"python-flask": {"error": "boom"}},
                     baseline_targets={"python-flask": {"judge_a": _judge()}})
    assert code == 1 and "run error" in out


# ---- P2: provenance classification ---------------------------------------

def _prov(**over):
    base = {
        "version": 2, "model": "deepseek-chat", "base_url": "https://api.deepseek.com",
        "engine_files": {"analysis/joern/backward_from_sinks.sc": "aaa"},
        "judge_scripts": {"scripts/llm_judge_sink_chains.py": "jjj",
                          "scripts/llm_judge_entrypoints.py": "jjj"},
        "targets": {"python-flask": {"tree_sha": "t1:3", "snippets_sha": "s1:2",
                                     "ep_snippets_sha": "e1:4", "chains_sha": "c1:1"}},
    }
    base.update(over)
    return base


def _freeze_provenance(monkeypatch, engine="aaa", judge="jjj", other="sss"):
    """Pin the current-side provenance to the values in _prov(), so a test
    exercises one classification signal at a time instead of tripping over
    the real (edited) rule/joern/judge file hashes."""
    def fake_sha(p):
        s = str(p)
        if "llm_judge" in s:
            return judge
        if "analysis/joern" in s:
            return engine
        return other

    monkeypatch.setattr(rb, "_sha256_file", fake_sha)
    monkeypatch.setattr(rb, "_engine_files", lambda: [
        REPO / "analysis" / "joern" / "backward_from_sinks.sc"])


def test_real_regression_when_nothing_moved(gate, monkeypatch):
    _freeze_provenance(monkeypatch)
    monkeypatch.setattr(rb, "_model_env", lambda: {"model": "deepseek-chat",
                                                   "base_url": "https://api.deepseek.com"})
    monkeypatch.setattr(rb, "TARGETS", {"python-flask": {"tree": "targets/python-flask"}})
    monkeypatch.setattr(rb, "_target_state", lambda *a, **k: dict(
        _prov()["targets"]["python-flask"]))
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 8, "recall_A": "8/10",
                                          "safe_fp": []}},
        baseline_targets={"python-flask": {"judge_a": _judge(), "judge_b": {}}},
        prov=_prov())
    assert code == 1
    assert "REAL_REGRESSION" in out


def test_model_drift_is_named(gate, monkeypatch):
    _freeze_provenance(monkeypatch)
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 8, "recall_A": "8/10",
                                          "safe_fp": []}},
        baseline_targets={"python-flask": {"judge_a": _judge(), "judge_b": {}}},
        prov=_prov(model="deepseek-v4-flash"))
    assert code == 1
    assert "MODEL_DRIFT" in out and "deepseek-v4-flash -> deepseek-chat" in out


def test_code_change_is_named(gate, tmp_path, monkeypatch):
    _freeze_provenance(monkeypatch)
    (tmp_path / "cache" / "python-flask").mkdir(parents=True)
    monkeypatch.setattr(rb, "TARGETS", {"python-flask": {"tree": "targets/python-flask"}})
    monkeypatch.setattr(rb, "_target_state", lambda *a, **k: {
        "tree_sha": "t2:3", "snippets_sha": "s9:2", "ep_snippets_sha": "e1:4",
        "chains_sha": "c1:1"})
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 8, "recall_A": "8/10",
                                          "safe_fp": []}},
        baseline_targets={"python-flask": {"judge_a": _judge(), "judge_b": {}}},
        prov=_prov())
    assert code == 1
    assert "CODE_CHANGED" in out and "SNIPPET_CHANGED(A)" in out
    assert "REAL_REGRESSION" not in out


def test_engine_change_is_named(gate, monkeypatch):
    """A rule/joern edit moves results with no target edit — D12's sinks-python
    arity fix was exactly this shape."""
    _freeze_provenance(monkeypatch)
    monkeypatch.setattr(rb, "TARGETS", {"python-flask": {"tree": "targets/python-flask"}})
    monkeypatch.setattr(rb, "_target_state", lambda *a, **k: dict(
        _prov()["targets"]["python-flask"]))
    monkeypatch.setattr(rb, "_engine_files", lambda: [
        REPO / "analysis" / "joern" / "taint_confirm.sc"])
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 8, "recall_A": "8/10",
                                          "safe_fp": []}},
        baseline_targets={"python-flask": {"judge_a": _judge(), "judge_b": {}}},
        prov=_prov())
    assert code == 1
    assert "ENGINE_CHANGED(" in out and "taint_confirm.sc" in out
    assert "REAL_REGRESSION" not in out


# ---- P3: extra dimensions -------------------------------------------------

def _seed_reports(tmp_path, monkeypatch, entries):
    """entries: [(name, mtime_offset_seconds, dict)] written under reports/."""
    root = tmp_path / "reports"
    now = time.time()
    for name, offset, data in entries:
        d = root / name
        d.mkdir(parents=True, exist_ok=True)
        p = d / "summary.json"
        p.write_text(json.dumps({"targets": data}))
        import os
        os.utime(p, (now + offset, now + offset))


def test_token_budget_uses_previous_batch_of_same_shape(gate, tmp_path, monkeypatch):
    """The frozen judge baseline is a different pipeline (one call per chain),
    so tokens are compared against the previous AGENT batch instead."""
    monkeypatch.setattr(rb, "_confirmed_rate", lambda n: None)
    _seed_reports(tmp_path, monkeypatch, [
        ("run-old", -600, {"python-flask": {"recall_A_hit": 10, "tokens": 1_000_000}}),
        ("run-mid", -300, {"python-flask": {"recall_A_hit": 10, "tokens": 1_000_000}}),
    ])
    under = {"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                              "safe_fp": [], "tokens": 1_100_000}}
    code, out = gate(summary_targets=under,
                     baseline_targets={"python-flask": {"judge_a": _judge()}},
                     max_token_delta=0.30)
    assert code == 0
    assert "+10%" in out
    over = {"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                             "safe_fp": [], "tokens": 1_900_000}}
    code, out = gate(summary_targets=over,
                     baseline_targets={"python-flask": {"judge_a": _judge()}},
                     max_token_delta=0.30)
    assert code == 1
    assert "over +30% budget" in out


def test_token_dimension_skips_without_reference(gate, tmp_path, monkeypatch):
    monkeypatch.setattr(rb, "_confirmed_rate", lambda n: None)
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                                          "safe_fp": [], "tokens": 5_000_000}},
        baseline_targets={"python-flask": {"judge_a": _judge()}},
        max_token_delta=0.30)
    assert code == 0
    assert "cost baseline: none" in out


def test_confirmed_rate_floor(gate, monkeypatch):
    monkeypatch.setattr(rb, "_confirmed_rate", lambda n: (13, 25))
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                                          "safe_fp": []}},
        baseline_targets={"python-flask": {"judge_a": _judge()}},
        min_confirmed_rate=0.60)
    assert code == 1
    assert "confirmed 13/25 = 52%" in out and "below floor 60%" in out
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                                          "safe_fp": []}},
        baseline_targets={"python-flask": {"judge_a": _judge()}},
        min_confirmed_rate=0.50)
    assert code == 0


def test_confirmed_rate_missing_is_skip(gate, monkeypatch):
    monkeypatch.setattr(rb, "_confirmed_rate", lambda n: None)
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                                          "safe_fp": []}},
        baseline_targets={"python-flask": {"judge_a": _judge()}},
        min_confirmed_rate=0.60)
    assert code == 0
    assert "no agent cache" in out


def test_forbid_leak_fails_on_recent_certain_record(gate, tmp_path):
    audit = tmp_path / "leak-audit.jsonl"
    summary = _write_summary(tmp_path, {"python-flask": {
        "recall_A_hit": 10, "recall_A": "10/10", "safe_fp": []}})
    # leak recorded AFTER the summary was written (a leak during the run)
    audit.write_text(json.dumps({"ts": "2099-01-01T00:00:00",
                                 "ts_epoch": summary.stat().st_mtime + 1,
                                 "where": "judge_a.build_prompt:routes.py:12",
                                 "severity": "certain", "kind": "marker_label",
                                 "match": "VULN: py-"}) + "\n")
    _write_baseline(tmp_path, {"python-flask": {"judge_a": _judge()}})
    code = rb.compare_with_baseline(summary, forbid_leak=True)
    assert code == 1


def test_forbid_leak_ignores_records_older_than_summary(gate, tmp_path):
    audit = tmp_path / "leak-audit.jsonl"
    audit.write_text(json.dumps({"ts": "2020-01-01T00:00:00",
                                 "ts_epoch": 1577836800.0, "where": "old",
                                 "severity": "certain"}) + "\n")
    code, out = gate(
        summary_targets={"python-flask": {"recall_A_hit": 10, "recall_A": "10/10",
                                          "safe_fp": []}},
        baseline_targets={"python-flask": {"judge_a": _judge()}},
        forbid_leak=True)
    assert code == 0
    assert "0 certain" in out


# ---- provenance helpers ---------------------------------------------------

def test_records_sha_ignores_joern_log_noise(tmp_path):
    """joern writes [INFO] lines to the same stdout as its JSONL payload, so
    raw hashes differ between identical runs; record hashes must not."""
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    recs = [{"sink": {"file": "db.py", "line": 16}, "chains": []},
            {"sink": {"file": "x.py", "line": 3}, "chains": [{"route": "/a"}]}]
    a.write_text("[INFO] run 1\n" + "".join(json.dumps(r) + "\n" for r in recs))
    b.write_text("[INFO] run 2 took longer\n" + "".join(json.dumps(r) + "\n" for r in recs))
    assert rb._records_sha(a) == rb._records_sha(b)


def test_records_sha_missing_file_is_none(tmp_path):
    assert rb._records_sha(tmp_path / "nope.jsonl") is None


def test_tree_sha_ignores_ground_truth(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "a.py").write_text("x = 1\n")
    before = rb.tree_sha(tree)
    (tree / "ground_truth.json").write_text('{"vulnerabilities": []}')
    (tree / "GROUND_TRUTH.md").write_text("# gt\n")
    assert rb.tree_sha(tree) == before
    (tree / "a.py").write_text("x = 2\n")
    assert rb.tree_sha(tree) != before


def test_read_baseline_tolerates_v1_flat(tmp_path, monkeypatch):
    flat = tmp_path / "baseline.json"
    flat.write_text(json.dumps({"python-flask": {"judge_a": _judge()}}))
    monkeypatch.setattr(rb, "BASELINE_FILE", flat)
    data = rb._read_baseline()
    assert data["version"] == 1
    assert "python-flask" in data["targets"]


def test_is_b_summary_detects_shape():
    assert rb._is_b_summary({"targets": {"py": {"recall_B": "7/7"}}}) is True
    assert rb._is_b_summary({"targets": {"py": {"recall_A": "10/10"}}}) is False
