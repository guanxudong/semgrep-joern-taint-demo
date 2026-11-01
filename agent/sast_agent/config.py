"""Configuration for the sast_agent package.

DeepSeek env loading mirrors scripts/llm_judge_sink_chains.py:
load_dotenv(), falling back to ~/Code/agent-demo/.env. Budget constants
below are tuned against the frozen baseline (run_baseline.py --compare).
"""

import os
import shutil
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional; minimal stdlib fallback
    def load_dotenv(path=None) -> bool:  # type: ignore[no-redef]
        p = Path(path) if path else Path(".env")
        if not p.exists():
            return False
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))
        return True


load_dotenv()
if not os.environ.get("DEEPSEEK_API_KEY"):
    load_dotenv(Path.home() / "Code" / "agent-demo" / ".env")

MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
API_KEY = os.environ.get("DEEPSEEK_API_KEY")

# Budgets
MAX_TOTAL_LLM_TOKENS = 2_000_000
MAX_JOERN_QUERY_RETRIES = 2
# 180s proved too tight: GAP sinks that drill down (many LLM round trips)
# and transient DeepSeek slowness both blew past it, producing synthesized
# not-vulnerable findings (false FNs) on the csharp-aspnet M3 run.
# (Kept at 600 for the tracer's per-step wall clock too.)
SINK_TIMEOUT_SECONDS = 600

# Adversarial review: per-role budgets for the attacker/defender agents.
# read/search only, so far fewer calls than tracing needs.
VERIFIER_MAX_TOOL_CALLS = 10
VERIFIER_TIMEOUT_SECONDS = 300

# Category-B planner: one agent run per target. The digest carries the
# whole route table; search/read calls are only for spot-checking
# decorators and binding shapes, so the budget is small.
PLANNER_MAX_TOOL_CALLS = 15
PLANNER_TIMEOUT_SECONDS = 600

# Category-B worker: per-hypothesis budgets. B-class drill-down is
# shallower than A-class (get_forward_slice hands over the whole slice in
# one call), so fewer tool calls; the timeout follows the old M3 SINK lesson.
WORKER_MAX_TOOL_CALLS = 15
WORKER_TIMEOUT_SECONDS = 600
# Per-target total token budget for B-class runs: worker+verifier burn
# ~2x an A-class sink (python-flask worker smoke hit the shared 2M cap).
WORKER_TOTAL_LLM_TOKENS = 3_000_000
# Concurrent hypotheses per target (tools are read-only, CPG/snippets
# cached; each vulnerable finding adds 2 concurrent verifier rounds, so
# peak in-flight LLM calls is ~3x this).
WORKER_CONCURRENCY = 3

# Tracer (A-class v2): structured trace-continuation state machine.
# Per-sink LLM cost ≈ steps + 1 verdict call, so the step budget is the
# real cap; the wall-clock budget reuses SINK_TIMEOUT_SECONDS semantics.
MAX_TRACE_STEPS_PER_SINK = 12

REPO = Path(__file__).resolve().parent.parent.parent
CACHE_ROOT = REPO / "workspace" / "agent-cache"


def cache_dir(target: str) -> Path:
    """Per-target cache dir workspace/agent-cache/<target>/ (created)."""
    d = CACHE_ROOT / target
    d.mkdir(parents=True, exist_ok=True)
    return d


def find_joern_parse() -> str:
    """joern-parse is not always on PATH; fall back to the joern-cli bundle."""
    return (os.environ.get("JOERN_PARSE")
            or shutil.which("joern-parse")
            or str(Path.home() / ".local" / "bin" / "joern-cli" / "joern-parse"))


JOERN_PARSE = find_joern_parse()

# Same shape as agent/run_baseline.py TARGETS.
# (python-flask-enterprise was user-deleted in D17/9947ba2 — do not
# re-register without restoring the tree.)
#
# The two non-HTTP targets (2026-11-01, user decision: everything under
# targets/ is in the test loop) use trigger-descriptor routes
# ("MSG <subject>" / "CMD <cmd>" / "FILE <kind>") and registry-shaped
# dispatch. Engine coverage is still HTTP-shaped in places (see
# LIMITATIONS.md §4): entrypoint detection and taint sources only see
# message/command/file reads since the same-day joern extension, and
# route-shape checks may score misses where function hits still work.
TARGETS = {
    "python-flask": {
        "rules": "analysis/rules/sinks-python.yml",
        "tree": "targets/python-flask",
        "ground_truth": "targets/python-flask/ground_truth.json",
    },
    "java-spring": {
        "rules": "analysis/rules/sinks-java.yml",
        "tree": "targets/java-spring",
        "ground_truth": "targets/java-spring/ground_truth.json",
    },
    "js-ts-express": {
        "rules": "analysis/rules/sinks-js.yml",
        "tree": "targets/js-ts-express",
        "ground_truth": "targets/js-ts-express/ground_truth.json",
    },
    "java-fix-gateway": {
        "rules": "analysis/rules/sinks-java.yml",
        "tree": "targets/java-fix-gateway",
        "ground_truth": "targets/java-fix-gateway/ground_truth.json",
    },
    "python-clearing-worker": {
        "rules": "analysis/rules/sinks-python.yml",
        "tree": "targets/python-clearing-worker",
        "ground_truth": "targets/python-clearing-worker/ground_truth.json",
    },
}


# Canaries (workspace/, NOT benchmark targets — never in --target all):
# hand-built scenes that exercise one mechanism end to end. M9 acceptance:
# canary-di is a registry-dispatch + module-variable staging relay, blind
# to both the call graph and the dataflow engine.
CANARIES = {
    "canary-di": {
        "rules": "analysis/rules/sinks-python.yml",
        "tree": "workspace/canary-di",
        "ground_truth": "workspace/canary-di/ground_truth.json",
    },
}


def target_cfg(target: str) -> dict:
    """Resolve a target name to its config (with absolute tree path)."""
    if target not in TARGETS and target not in CANARIES:
        raise ValueError(f"unknown target: {target} (known: {list(TARGETS)}, "
                         f"canaries: {list(CANARIES)})")
    cfg = dict(TARGETS.get(target) or CANARIES[target])
    cfg["tree_path"] = REPO / cfg["tree"]
    return cfg
