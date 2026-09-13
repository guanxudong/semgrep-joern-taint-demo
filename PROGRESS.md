# Progress

Status of the Semgrep + Joern taint-confirmation pipeline as of 2026-07.
Companion docs: `LIMITATIONS.md` (known gaps), `DECISIONS.md` (what we
decided to do about them).

## Agent MVP — M0 baseline frozen (2026-08)

`agent/run_baseline.py` (part of the `AGENT_MVP_PLAN.md` milestones) runs the
full deterministic pipeline + both LLM judges per target and freezes the
numbers in `workspace/baseline/baseline.json` (artifacts per target in
`workspace/baseline/<target>/`; every step cached, `--collect-only`
recomputes the summary). First freeze:

| target | chains CONFIRMED | A recall | B recall | B safe FP |
|---|---|---|---|---|
| python-flask | 22/25 | 10/10 | 7/7 | py-safe-02 |
| java-spring | 21/22 | 8/10 | 7/7 | java-safe-02 |
| js-ts-express | 24/35 | 10/10 | 7/7 | js-safe-02 |
| csharp-aspnet | 22/32 | 10/10 | 6/7 | cs-safe-02 |
| jsp-legacy | 29/32 | 9/10 | 7/7 | jsp-safe-05 |

Deltas vs the 2026-07 numbers above, all tooling drift (not code changes):
- semgrep 1.168 finds more sink call sites on js/cs (17 and 15 sinks),
  inflating chain totals (was 28/25); CONFIRMED counts went UP (24/22 vs
  22/18), no regression. jsp needed `--no-git-ignore` (workspace/ is
  gitignored; now baked into both `run_baseline.py` and
  `agent/sast_agent/pipeline.py`).
- DeepSeek endpoint model drift: A-class FNs are java-cmdi-01/02 and
  jsp-cmdi-02 — the model now argues `Runtime.exec(String)`/`exec` without a
  shell is not exploitable (flag-injection still possible; ground truth
  stands). B-class: safe-02 (ownership-checked IDOR) FP'd on 4 targets,
  cs-safe-05 flipped too, cs B has 1 FN. Judgment-layer variance, baseline
  re-pinned to current model behavior for future regression gating (M5).

## Agent MVP — M3 dynamic drill-down done (2026-08-12)

M1 (tool layer) / M2 (per-sink investigation agent) / M3 (drill-down:
read_function / search_code / joern_query + playbook + mechanical evidence
validation) of `AGENT_MVP_PLAN.md` are complete; details and handoff notes
in `agent/HANDOFF.md`. Full 5-target regression of
`uv run agent/run_agent.py`:

| target | A recall (frozen baseline) | SAFE FP | tokens |
|---|---|---|---|
| python-flask | 10/10 (10/10) | none | 171k |
| java-spring | 10/10 (8/10) | none | 149k |
| js-ts-express | 10/10 (10/10) | none | 251k |
| csharp-aspnet | 10/10 (10/10) | none | 363k |
| jsp-legacy | 10/10 (9/10) | none | 348k |

The §6A drill-down targets all pass with violation-free evidence:
js-sqli-02 (module variable `pendingName` relay, LIKELY), cs-cmdi-02 and
cs-path-traversal-01 (C# `Services/` cross-file, LIKELY). M3 fixes (agent
side only): sink timeout 180→600s (DeepSeek slowness caused synthesized
not-vulnerable FNs on cs), evidence-validation layer de-noised (per-entry
identifier union, code_read-only, prose stopwords, tolerant ref parsing),
XXE prompt rule hardened against parameter-entity theory (js-safe-03 FP
eliminated). Next: M4 verifier, M5 batch + regression gate.

## Agent MVP — M4 adversarial review done (2026-08-12)

M4 of `AGENT_MVP_PLAN.md` (§7): `agent/sast_agent/verifier.py` runs two
independent rounds on every vulnerable verdict — attacker (construct a
concrete trigger request) and defender (hunt an effective sanitizer with
cited refs) — and `report.apply_verifier()` merges them mechanically
(plan §4): attacker failure downgrades one level, a defender sanitizer
with resolvable refs vetoes the verdict to not-vulnerable. Details in
`agent/HANDOFF.md`. Acceptance + full 5-target regression:

| target | A recall | SAFE FP | tokens (M3) |
|---|---|---|---|
| python-flask | 10/10 | none | 603k (171k) |
| java-spring | 10/10 | none | 597k (149k) |
| js-ts-express | 10/10 | none | 755k (251k) |
| csharp-aspnet | 10/10 | none | 858k (363k) |
| jsp-legacy | 10/10 | none | 969k (348k) |

- Acceptance smoke (`agent/smoke_verifier.py --target all`): every SAFE
  category-A sample with a finding was forced to vulnerable/CONFIRMED and
  the defender vetoed 9/9 back (parameterized queries, allow-lists,
  hardened XML parsers all correctly identified). Shared sinks (vuln and
  safe chains through one sink) are excluded by the scoring's
  primary-chain rule.
- Real-run collateral damage: zero — no false vetoes, no attacker
  downgrades, no failed rounds; the three M3 drill-down targets stay
  vuln=True LIKELY with violation-free evidence.
- Cost: verifier roughly doubles-to-triples token spend (two extra agent
  runs per vulnerable sink). Parallelism / context trimming is an M5
  consideration.

## Agent MVP — M5 batch mode + regression gate (2026-08-15)

M5 of `AGENT_MVP_PLAN.md` (§8-M5), details in `agent/HANDOFF.md`:

- `agent/run_agent.py --target all`: runs every target with parallelism 2
  (one asyncio loop per target thread; joern memory caps it), writes
  reports to `workspace/agent-reports/<date>/<target>/` plus an aggregate
  `summary.json` (per-target recall/FP/tokens). Same-day reruns get a
  time-suffixed dir instead of clobbering; single-target mode unchanged.
- `agent/run_baseline.py --compare [summary.json]`: regression gate
  against the frozen `workspace/baseline/baseline.json` — non-zero exit
  when a compared target's category-A recall drops below the baseline
  judge_a recall, or a NEW safe-sample FP appears (baseline-known FPs
  tolerated). Targets missing from the summary are reported as skipped.
- Validated: gate self-test on fabricated summaries (PASS / recall-drop /
  new-FP) plus a `--limit 1 --no-verify` batch smoke whose summary the
  gate correctly rejected end-to-end. Full 5-target batch regression
  (2026-08-15, verifier on): A recall 10/10 everywhere, 0 safe FPs,
  ~3.62M tokens, ~32 min wall clock (vs ~105 min sequential in M4);
  `--compare` GATE: PASS. Per-target confidence splits: see the M5 table
  in `agent/HANDOFF.md`.

## Agent MVP — M6 category-B planner done (2026-09-03)

M6 of `AGENT_MVP_PLAN.md` (§7A): the hypothesis-driven queue for category B.
New `agent/sast_agent/planner.py` (one planner run per target over a compact
repo-map route digest; mandatory trait→class mappings — the model must submit
a hypothesis for every route matching a trait even when a guard is visible,
since guard-effectiveness is the M7 worker's call) plus two new SastTools:
`submit_hypotheses` (Hypothesis contract, 7-class validation, appends to
`workspace/agent-cache/<target>/hypotheses.jsonl` — the M7 input queue) and
`get_forward_slice` (wraps `extract_entrypoint_snippets.sc` via
`pipeline.get_entrypoint_snippets`, GT markers stripped). CLI
`agent/run_planner.py --target <name|all>` runs the planner and then checks
route coverage of every ground-truth category-B entry (validation only —
ground truth never reaches the agent); exit 1 below 100%.

Acceptance run (2026-09-03, 5 targets sequential): **B-route coverage
45/45** (7 vuln + 2 safe B routes per target), 14–18 hypotheses per target,
~272k tokens total, ~6.4 min wall clock. Prompt iteration that mattered:
heuristics as *mandatory* mappings — as plain heuristics the planner
verified the code, saw the guard, and dropped every safe-02/05 route. Next:
M7 (B-class worker playbook + absence comparison, consuming
hypotheses.jsonl), M8 (taxonomy coverage checklist + B-class gate).

## Agent MVP — M8 taxonomy checklist + B-class gate done (2026-09-05)

M8 of `AGENT_MVP_PLAN.md` (§7A 完整性约束 / §8-M8), the final milestone —
M0–M8 now all closed. Details in `agent/HANDOFF.md`:

- **Taxonomy coverage checklist** (§7A: in a no-ground-truth environment
  this is the only visible B-recall guarantee): the planner's
  `submit_hypotheses` tool now takes a mandatory `coverage` argument — one
  `TaxonomyEntry` per B class (routes_examined / submitted / excluded with
  per-route reasons). Validated tolerantly (missing classes auto-filled
  from the queue, flagged `"derived"`), written to
  `workspace/agent-cache/<target>/taxonomy_checklist.json`, and rendered by
  `render_markdown_b` into a trailing `## Taxonomy coverage audit` table in
  `report_b.md` (`finalize_target_b` passes it through from the cache).
- **Regression gate extended to B**: `run_baseline.py --compare`
  auto-detects `summary.json` (A-class, gated on judge_a) vs
  `summary_b.json` (B-class, gated on judge_b) by content; recall drop or a
  NEW safe-sample FP (beyond the baseline-known py/java/js/cs-safe-02)
  exits non-zero. `_latest_summary()` globs both summary shapes.
- Acceptance: `agent/smoke_m8.py` 25 no-LLM checks green; planner re-run on
  all 4 targets (≈300k tokens total) produced complete 7-class checklists
  with zero derived fallbacks and 9/9 GT route coverage each (M6 gate
  PASS); the B gate run end-to-end on the real M7 acceptance
  `summary_b.json` → **GATE: PASS** (4/4 targets).

## Agent MVP — M7 category-B worker implemented (2026-09-04)

M7 of `AGENT_MVP_PLAN.md` (§7A): the per-hypothesis worker + absence-
comparison playbook. New `agent/sast_agent/worker.py` (clones the
investigator skeleton — per-hypothesis agent, _ToolGuard budget warning,
asyncio timeout + UsageLimits, ToolCallPart submission extraction, honest
synthesized fallback; tools = get_forward_slice + GT-stripped
read_function/search_code + submit_b_finding, no joern_query), `BFinding`
contract + `Evidence.kind "absence_comparison"`, `tools.submit_b_finding`,
B-class attacker/defender rounds in verifier.py (attacker constructs a
concrete over-reach request; defender hunts middleware/framework-level
guards the forward slice cannot see), `report.assign_confidence_level_b` /
`apply_verifier_b` / `apply_validation(b_class=True)` (CONFIRMED requires
absence_comparison evidence) / `score_b_findings` (mirrors
`llm_judge_entrypoints.py` best-strength matching) / `render_markdown_b`,
budgets `WORKER_MAX_TOOL_CALLS=15` / `WORKER_TIMEOUT_SECONDS=600`, and CLI
`agent/run_worker.py --target <name|all> [--limit N] [--no-verify]
[--dry-run]` writing `workspace/agent-reports/<date>-m7/<target>/
{findings_b.jsonl,report_b.md}` + `summary_b.json`.

Implementation verified (2026-09-04, no LLM calls): py_compile on all
touched files; import + unit smoke (BFinding round-trip, confidence
mapping, prompt rendering without leftover `.format()` placeholders,
submit_b_finding accept/reject, scorer TP on a real matching finding +
type-mismatch FN, validation B-rule downgrade, verifier veto with
resolvable ref + hallucinated-ref veto ignored); `--dry-run` end-to-end
for all 5 targets (queue load → stub findings → validation → scoring →
report_b.md + summary_b.json; every gt B entry matched by ≥1 hypothesis).

**Acceptance run (2026-09-04 23:31, jsp-legacy excluded by user decision):
PASS on all 4 targets** — `workspace/agent-reports/2026-09-04-233106-m7/`:

| target | recall_B (baseline) | SAFE FP | tokens |
|---|---|---|---|
| python-flask | 7/7 (7/7) | py-safe-02 (baseline-known) | 2.14M |
| java-spring | 7/7 (7/7) | java-safe-02 (baseline-known) | 2.52M |
| js-ts-express | 7/7 (7/7) | js-safe-02 (baseline-known) | 1.97M |
| csharp-aspnet | 7/7 (**6/7**) | cs-safe-02 (baseline-known) | 2.75M |

0 new SAFE FPs (exactly the baseline's own four); 48 CONFIRMED findings
all carry absence_comparison evidence, 190 file:line refs spot-verified
on disk (0 bad); 0 GT-label leakage in finding text. Wall clock ~27 min
with `WORKER_CONCURRENCY=3` (hypothesis-level asyncio.gather; cold-joern
cache warmed sequentially first). Fixes made during acceptance: GT-tag
strip now handles line-numbered/rg-prefixed tool output (the old
`^`-anchored regex silently leaked `VULN:`/`SAFE:` labels through
read_function/search_code — first run discarded); B-class token budget
split out as `WORKER_TOTAL_LLM_TOKENS=3M`; one retry on transient API
errors. `--exclude` flag added to run_worker.py for selective batch runs.

**jsp-legacy removed (2026-09-05, user decision)**: the target and
`scripts/jsp_to_java.py` were `git rm`'d (recoverable from history);
config/run_baseline TARGETS entries and doc references cleaned. Dormant
leftovers by design: the `out.print` branch in sinks-java.yml, joern
`_jspService` detection, and the scorers' `_jsp.java→.jsp` normalization.

## Done and validated

- `targets/jsp-legacy/` + `scripts/jsp_to_java.py` (2026-07, D8): new
  scriptlet-JSP target mirroring the java-spring taxonomy one-for-one
  (20 entries, `jsp-` ids) plus a line-preserving JSP→Java transpiler.
  Validated: transpiler output parses with javasrc2cpg and Semgrep runs
  clean on it, hitting 9/10 category-A sinks (all but jsp-xss-01, whose
  `out.print` shape the return-based xss rule cannot match — see
  `targets/jsp-legacy/GROUND_TRUTH.md`). Wired end-to-end by D9 (below).

- `analysis/joern/taint_confirm.sc` built and validated across all four
  targets: Semgrep sink -> call-graph backward trace -> DFG confirmation.
  Raw outputs: `/tmp/taint_{py,java,js,cs}.jsonl`.
- Instance-field flows confirm correctly in Python / Java / C#
  (`self._pending_name`, `this._target` style deep chains).
- In-controller C# sinks confirm; Python/Java/JS deep chains confirm.
- Supporting scripts in place: `find_entrypoints.sc`,
  `backward_from_sinks.sc`, `forward_from_entrypoints.sc`,
  `extract_chain_snippets.sc` (disk-sliced via `SRC_ROOT` because the Python
  frontend stores no method source), `scripts/semgrep_to_sinks.py`.
- **D1–D4 implemented and re-validated on all four targets** (chain-level
  report: py 22/25, java 21/22, js 22/28, cs 18/25 chains CONFIRMED):
  - D1 (route-parameter sources, `taint_confirm.sc`): python Flask `<...>` /
    FastAPI `{...}` handler params (pysrc2cpg has no decorator annotations —
    handlers resolved as the next `def` after the route call's line); java
    Spring + JAX-RS annotated params; js Koa/Fastify/Hapi accessor calls;
    csharp any `[Http*]`-annotated action's params. Validated:
    `get_user` -> `db.py:16` and `delete_user` -> `db.py:37` now CONFIRM.
  - D2 (sink-name-first matching, `taint_confirm.sc` +
    `backward_from_sinks.sc`): ±3 window, name match ranked
    name < methodFullName (signature stripped) < `new X` code; constructor
    sinks matched by type name. Validated: `java-ssti-01` now picks
    `new Template(...)` (not `new Configuration(...)`) and CONFIRMS.
  - D3 (chain-level report): `backward_from_sinks.sc` emits JSONL via
    `CHAINS_JSON`; new `scripts/chain_report.py` joins chains with taint
    flows into per-chain CONFIRMED/UNCONFIRMED/NO_CHAIN.
  - D4 (flow dedup/cap): 3 flows per entrypoint instead of 5 per sink.
    Validated: `db/index.js:13` keeps the DELETE `/users/:id` chain
    CONFIRMED while the static-SQL GET `/users` chain is correctly
    UNCONFIRMED instead of crowded out.

## JSP pipeline wiring (2026-07, D9 — validated end-to-end)

The java pipeline now runs on the transpiled JSP tree with three small
additions (details in DECISIONS.md D9): the `out.print(...)` xss sink
pattern (+ `print` in the java sink-name tables), `_jspService` entrypoint
detection in all five joern scripts (route by filename convention,
`pages/X_jsp.java` → `"/X.jsp"`), and `X_jsp.java`→`X.jsp` file
normalization in both LLM judges. Full run on `workspace/jsp-java`:

- Semgrep: 16 sink findings, all 10 category-A vuln sinks covered
  (jsp-xss-01 now hits; the 6 extras are HTML-concat `out.print` calls in
  other pages plus the two safe XXE/path-traversal lookalikes — same
  shape-based noise profile as the other targets).
- Chain report: 32 chains, **29 CONFIRMED / 3 UNCONFIRMED / 0 NO_CHAIN**.
  The deep field-based chains (jsp-sqli-02 via `UserService.pendingName`,
  jsp-cmdi-02 via `ToolService.target`) CONFIRM like java-spring's. The 3
  UNCONFIRMED are genuinely untainted (static-SQL admin listing, DB-output
  print) — correct negatives.
- `taint_confirm.sc` unchanged: 15/16 sinks CONFIRMED.
- LLM judges (deepseek-v4-flash): **category A 10/10, category B 7/7,
  safe samples 5/5 correctly rejected (0 FPs), 0 LLM errors.**
- No ground-truth label leak: the transpiler drops `<%-- VULN --%>`
  comments and javasrc2cpg method slices exclude the `// VULN:` lines in
  the copied helpers (verified on the extracted snippets, 0 leaks).
- Regression: semgrep output on `targets/java-spring` byte-identical
  before/after the xss rule change; entrypoint detection on the four
  existing CPGs gains zero JSP entries (none have `*_jsp.java` files).

## Known gaps (details in LIMITATIONS.md)

- Joern OSS dataflow: JS module-level variables not tracked
  (`js-sqli-02`); C# cross-file flows lost past `Services/` (3 sinks report
  NO_CHAIN: `Services/FileService.cs`, `Services/ToolService.cs`) —
  csharpsrc2cpg frontend limit.
- Structural: sanitizers invisible to dataflow (by design, LLM layer's job);
  backward chains miss the write side of field passing (`stage_name` store
  site absent from LLM snippets); forward script over-tags sinks by name;
  Semgrep name-based rules flag intermediate forwarding calls (2 of the 3 js
  NO_CHAIN sinks); JS flow attribution only works for direct route lambdas.
- Config-constructor sinks (e.g. `XMLParser(resolve_entities=True)`) are now
  matched faithfully (D2) but show UNCONFIRMED because taint enters via the
  sibling parse call (`fromstring`), which CONFIRMS separately — expected
  per-node semantics, not a missed vuln.

## LLM judgment layer (2026-07, first run)

`scripts/llm_judge_sink_chains.py` (pydantic-ai + DeepSeek `deepseek-v4-flash`,
PromptedOutput — thinking mode rejects forced `tool_choice`) judges every
sink→entrypoint chain from `extract_chain_snippets.sc` against
`ground_truth.json`. First full run, category-A recall (before the
`methodSource` fix — see the note in the category-B section):

- python 10/10, js 9/10, csharp 8/10, java 7/10 → **34/40 = 85%**
- Safe samples: 17/20 correctly rejected; the 3 FPs are all safe-XXE
  (py/java/js — model does not credit defusedxml / secure factory config /
  `noent:false`; csharp judged correctly).
- FN causes: java-sqli-02 / java-cmdi-02 / java-xss-01 — SIGNATURE-ONLY
  snippets from javasrc2cpg (model saw no method bodies; root cause found
  via the category-B path, fixed below); js-sqli-02 — NO_CHAIN (D5
  module-var gap); cs-cmdi-02 / cs-path-traversal-01 — NO_CHAIN (D7
  csharpsrc2cpg drops CALL edges into Services/).
- Category B stays 0/28: sink rules don't fire for non-sink classes
  (expected; needs the forward-analysis approach, not the LLM layer).

Re-run after porting the `methodSource` fix to `extract_chain_snippets.sc`
(same model, same sinks): **java 7/10 → 10/10**, java-safe-03 FP cleared
(model now sees the secure XML factory config) → **37/40 = 92.5%**,
safe-sample FPs down to 2/20 (py/js safe-XXE — a prompt-tuning issue, not
snippets). csharp 8/10 unchanged: its FNs are NO_CHAIN (D7), which snippet
quality cannot fix.

Re-run after the D5 ghost-callee repair (below): **js 9/10 → 10/10**
(js-sqli-02 now has chains: lookup → findStaged → db.query) →
**38/40 = 95%**. Only cs-cmdi-02 / cs-path-traversal-01 (D7) remain.

Re-run after the D7 text fallback (below): **csharp 8/10 → 10/10** →
**category A: 40/40 = 100%**, safe-sample FPs 2/20 (py/js safe-XXE —
prompt tuning, see backlog).

## Ground-truth label leak (2026-07, found & fixed)

The `VULN: id` / `SAFE: id` marker comments above each handler were
leaking into LLM prompts: pysrc2cpg and csharpsrc2cpg start the method
line range at the comment/attribute line, so the disk slice included the
marker (cs A 16/16 sinks, cs B 24/24, py B 15/24, py A 7 sinks; js/java
clean). Both judge scripts now strip marker lines in `build_prompt`
(`strip_gt_tags`). Clean re-runs (same snippets, same model):

- A: py 10/10, cs 10/10 — **unchanged, 40/40 = 100% stands**
- B: py 7/7 unchanged; **cs dropped 7/7 → 5/7** — cs-business-logic-01 and
  cs-race-condition-01 had genuinely relied on the label: the forward BFS
  missed `_orderService.Transfer(...)` nested in `Ok(...)` (the D7 gap in
  the FORWARD direction), so the model correctly answered "no evidence".
  Added the same text fallback (forward variant) to
  `extract_entrypoint_snippets.sc` → cs back to **7/7, now honestly**.
- Final clean totals: **A 40/40, B 28/28**; FPs py-safe-03, js-safe-03
  (XXE prompt), js-safe-05 (spinlock strictness).

## Repo map (2026-07, built & compared)

LLM-consumable repository maps (directory tree + roles, HTTP route table,
per-file symbol index, file-level reference graph), same JSON schema from
two implementations, cross-checked against `ground_truth.json` with
`scripts/compare_repo_maps.py` (details: `analysis/repo_map_compare.md`):

- `scripts/repo_map.py` (tree-sitter, `uv run`, zero prerequisites,
  ~0.1 s/target) — **the default**. Route hits 22/22 on all four targets;
  function hits 22/22 except js 19/22 (3 misses are ground-truth logical
  names for anonymous arrow handlers — unrecoverable ceiling).
- `analysis/joern/repo_map.sc` (CPG-derived; needs an existing CPG, ~5 s
  JVM overhead) — equal route accuracy but sparser reference edges
  (call-based vs import-based; cs 5 vs 10). Kept as an enrichment source
  when a CPG already exists, not as a standalone mapper.
- Anonymous js/ts handlers get stable path-derived names (`/users/search` →
  `search`) in both implementations.

## Category-B forward-analysis path (2026-07, built)

`analysis/joern/extract_entrypoint_snippets.sc` dumps every HTTP entrypoint
plus the source of its forward-reachable callees (BFS depth ≤ 5, ≤15
methods, JSONL per entrypoint); `scripts/llm_judge_entrypoints.py` asks the
LLM for a verdict on ALL 7 non-sink classes per endpoint and scores the
category-B entries of `ground_truth.json` (file+function match, route
fallback). Original `scripts/llm_judge.py` renamed to
`scripts/llm_judge_sink_chains.py` (category A). First full B run
(24 entrypoints/target, deepseek-v4-flash):

- python 7/7, java 7/7, csharp 7/7, js 7/7 → **28/28 = 100% recall**
- B safe samples: 7/8 correctly rejected. The 1 FP is js-safe-05 —
  the model calls the `while(locked); locked=true` spinlock a non-atomic
  check-then-set (conf 0.85); debatable but strict.
- Fixes that mattered: (1) js/ts handlers are anonymous `<lambda>N`, so
  scoring falls back to file+route and keeps only the MOST SPECIFIC
  suffix match — otherwise the vulnerable `GET /:id` record also matched
  the safe `GET /users/me/:id` entry and manufactured an FP; (2)
  javasrc2cpg fills method `code` with only the SIGNATURE line, so
  `methodSource` now prefers a disk slice whenever it is longer —
  without bodies the model answered "no implementation shown" on every
  java FN. The same signature-only flaw existed in
  `extract_chain_snippets.sc` (category-A path) — ported there too; see
  the re-run note in the section above.
- csharp recall holds despite D7 (missing CALL edges into Services/):
  the B-class flaws are visible in the controller bodies alone.

## Remaining backlog — empty (2026-09-10)

The 2026-07 do-later round is closed — D5 and D7 are RESOLVED (details in
DECISIONS.md). The two leftovers were re-evaluated 2026-09-10 against the
project principle (AI SAST: when the LLM layer already covers a gap at the
recall ceiling, engine-side machinery must justify itself by changed
verdicts, not elegance) and both were dropped:

- ~~D6 (write sites in chain snippets)~~ — the M3 drill-down playbook covers
  it dynamically with violation-free evidence; mechanical enrichment would
  save tokens but change no verdict. See DECISIONS.md D6.
- ~~taint_confirm.sc dataflow side of D5/D7~~ — the engine DFG still cannot
  confirm JS module-variable / C# cross-`Services/` flows (factual record
  kept in LIMITATIONS.md §2), but the agent's manual relay plus verifier
  covers recall; a fix would only relabel LIKELY→CONFIRMED on those few
  cases, not change any verdict. Not worth the script complexity.

No open engine-side work items. Future improvement effort goes to the
LLM/agent layer (directions recorded in AGENT_MVP_PLAN.md §10).
