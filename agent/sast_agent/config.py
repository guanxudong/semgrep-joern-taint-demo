"""Configuration for the sast_agent package (M1).

DeepSeek env loading mirrors scripts/llm_judge_sink_chains.py:
load_dotenv(), falling back to ~/Code/agent-demo/.env. Budget constants are
the MVP defaults from AGENT_MVP_PLAN.md §6 (tune after benchmark).
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

# Budgets (AGENT_MVP_PLAN.md §6)
MAX_TOOL_CALLS_PER_SINK = 25
MAX_TOTAL_LLM_TOKENS = 2_000_000
MAX_JOERN_QUERY_RETRIES = 2
# 180s proved too tight: GAP sinks that drill down (many LLM round trips)
# and transient DeepSeek slowness both blew past it, producing synthesized
# not-vulnerable findings (false FNs) on the csharp-aspnet M3 run.
SINK_TIMEOUT_SECONDS = 600

# M4 adversarial review (AGENT_MVP_PLAN.md §7): per-role budgets for the
# attacker/defender agents. read/search only, so far fewer calls than the
# investigator needs.
VERIFIER_MAX_TOOL_CALLS = 10
VERIFIER_TIMEOUT_SECONDS = 300

# M6 category-B planner (AGENT_MVP_PLAN.md §7A): one agent run per target.
# The digest carries the whole route table; search/read calls are only for
# spot-checking decorators and binding shapes, so the budget is small.
PLANNER_MAX_TOOL_CALLS = 15
PLANNER_TIMEOUT_SECONDS = 600

# M7 category-B worker (§7A): per-hypothesis budgets. B-class drill-down is
# shallower than A-class (get_forward_slice hands over the whole slice in
# one call), so fewer tool calls; the timeout follows the M3 SINK lesson.
WORKER_MAX_TOOL_CALLS = 15
WORKER_TIMEOUT_SECONDS = 600
# Per-target total token budget for B-class runs: worker+verifier burn
# ~2x an A-class sink (python-flask M7 smoke hit the shared 2M cap).
WORKER_TOTAL_LLM_TOKENS = 3_000_000
# Concurrent hypotheses per target (tools are read-only, CPG/snippets
# cached; each vulnerable finding adds 2 concurrent verifier rounds, so
# peak in-flight LLM calls is ~3x this).
WORKER_CONCURRENCY = 3

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
    "csharp-aspnet": {
        "rules": "analysis/rules/sinks-csharp.yml",
        "tree": "targets/csharp-aspnet",
        "ground_truth": "targets/csharp-aspnet/ground_truth.json",
    },
}


def target_cfg(target: str) -> dict:
    """Resolve a target name to its config (with absolute tree path)."""
    if target not in TARGETS:
        raise ValueError(f"unknown target: {target} (known: {list(TARGETS)})")
    cfg = dict(TARGETS[target])
    cfg["tree_path"] = REPO / cfg["tree"]
    return cfg
