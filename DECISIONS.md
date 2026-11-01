# Decisions

Decision record for the Semgrep + Joern + LLM pipeline. Each live entry
states the decision and the rationale; execution order and outcomes live in
`PROGRESS.md`. Entries implemented and closed long ago are compressed to
one-liners in the archive index at the bottom — full texts are recoverable
from git history (pre-2026-11-01 revisions of this file).

## Target coverage (2026-11-01)

### D18. C# targets removed: csharpsrc2cpg cannot rebuild CPGs on this host

Gap: on 2026-11-01 a re-parse of `csharp-aspnet` silently produced a
0-method empty CPG — `csharpsrc2cpg`'s `dotnetastgen-macos` is an x86_64
binary and this arm64 host has no Rosetta (LIMITATIONS.md §3). Any future
csharp source edit would trigger `pipeline.ensure_cpg` to rebuild into
that empty CPG, so the target can no longer be honestly re-benchmarked
here. Generic C# *tooling* (tree-sitter repo-map extraction, the
joern-script C# fallbacks) is language-generic and stays; only the
benchmark targets go.

Decision (user): remove both C# targets — `targets/csharp-aspnet` and its
non-HTTP mirror `targets/csharp-fix-gateway` (D17) — from the repo, and
drop the `csharp-aspnet` entry from `run_baseline.py`'s TARGETS (the next
freeze prunes it from `baseline.json`, same mechanism as jsp-legacy).
Benchmark scope going forward: the three engine-backed web stacks
(java-spring / js-ts-express / python-flask) plus the engine-backed
java-fix-gateway, with perl-cgi / perl-clearing-worker kept deliberately
as the no-engine tier-3 degraded-mode targets. Recoverable from git
history (e.g. after `softwareupdate --install-rosetta`).

### D19. Investigator path retired: the tracer is the only A-class path

Context: since M9 (2026-11-01) the A-class investigation had two
implementations side by side — the original free-form investigator
playbooks (LLM with five tools, full-history replay) and the tracer state
machine. The standing arrangement: the old path stays until the tracer
passes the frozen baseline gate.

On 2026-11-01 the tracer passed the gate end to end
(`run_baseline.py --compare` on the full batch: A recall 10/10 on all
three web targets — java-spring above its frozen 8/10 — 0 new safe-sample
FPs, GATE: PASS), so the old path was deleted the same day: `agent/run_agent.py`,
`sast_agent/investigator.py`, `tools.submit_finding`, and the
investigator-only budget constant. `run_trace.py` inlined the
`finalize_target` post-run tail it previously imported from run_agent.
Retired docs (closed-MVP spec, handoff, investigator walkthrough) went
with it — all recoverable from git history. The B-class planner/worker
playbooks are unchanged; the attacker/defender verifier is shared by both
classes and stays.

## Answer-leak hardening (2026-09-26)

### D15. No in-source markers anywhere; Perl target born marker-free

Gap: the targets used to carry `VULN:`/`SAFE:` marker comments above
every entry plus *descriptive* spoiler comments ("Sink: executes a SQL
string...", "No validation of amount sign -> negative amount steals
money") that no stripping rule covered — any read of the raw source
handed the LLM the answers.

Decision (user): retire the in-source marker convention in ALL targets
and scrub every spoiler comment — marker lines deleted, flaw-explaining
comments deleted or reworded to neutral functional descriptions (code,
identifiers, and ground truth untouched). The `_GT_TAG` stripping
machinery stays as harmless defense-in-depth (hardened into the single
scrubber of D16). Suggestive identifiers (`query_unsafe` etc.) were kept
because ground truth references them; renaming is only allowed together
with a ground-truth update (recorded in AGENTS.md).

Same decision round: `targets/perl-cgi/` was created as the tier-3
no-engine degraded-mode case of D10 (legacy CGI.pm style, one `.pl`
script per action under `cgi-bin/`, routes by filename convention,
22-entry mirror of the small targets, `pl-` ids) — no Semgrep grammar, no
Joern frontend. It follows the no-marker rule from birth and uses neutral
identifiers (safe variants named `searchV2`/`search_prepared` etc., not
`*_safe`). Pipeline registration is deliberately NOT done yet — that is
the D10 integration work.

## Measurement integrity (2026-10-04)

### D16. One scrubber with a mechanical leak assertion; a gate that explains itself

Gap found while auditing the measurement layer (not the pipeline):
1. **The scrubber had four divergent copies.** Two `^`-anchored regexes in
   the judge scripts and two unanchored ones in the agent tool layer. The
   divergence is exactly what let a labelled `rg` line through once (M7
   acceptance). D15 then removed every marker from every target, so the
   repo lost its natural fixture and any future regression in the scrub
   would have been silent — LIMITATIONS §4 classes leak paths as "a class
   of issue, not a fixed bug".
2. **The gate failed for the wrong reason.** A target registered in
   TARGETS but frozen with `--skip-llm` left `judge_a`/`judge_b` empty,
   and `compare_with_baseline()` read that as "recall unparseable" → FAIL.
   Every full batch run was guaranteed to exit 1 for reasons unrelated to
   code quality.
3. **A recall drop carried no cause.** Code edit, snippet change, rule/joern
   change and model drift all surfaced as the same red row. Model drift had
   already forced two baseline re-pins (2026-08, 2026-09) with no way to
   distinguish it from a real regression.
4. **Only two gated dimensions.** Cost and confirmed rate had no guardrail.

Decisions:
- **Single scrubber, `agent/sast_agent/scrub.py`** (dependency-free,
  ground-truth-blind by construction): `strip_gt_tags()` covers every known
  label shape and `find_gt_leak()` classifies survivors as `certain`
  (a `VULN:`/`SAFE:` label survived → the strip failed) or `suspected`
  (a bare `<lang>-<type>-<nn>` id literal). `scrub()` strips, then
  ASSERTS: certain → append to `workspace/leak-audit.jsonl` and raise
  `GroundTruthLeak`. The id pattern is a hardcoded shape, never read from
  `ground_truth.json` — the tool layer must not touch ground truth (red
  line). Suspected hits are audited, not fatal, because a real repo may
  legitimately name a fixture after a CVE-style id.
- **Assertion choke points, not per-call-site code**: `SastTools` scrubs
  `read_function` / `search_code` / `get_chain_snippets` /
  `get_forward_slice`, and both judges scrub the assembled `build_prompt`.
  New callers cannot forget.
- **`--check-leak` on both judges** builds every prompt and asserts, with
  no API key, so the leak guard is testable offline.
- **Gate verdicts are PASS / SKIP / FAIL.** SKIP = "not comparable" and
  never fails the gate; `--require-baseline` promotes it to FAIL for
  strict runs.
- **`baseline.json` is version 2**: `{version, provenance, targets}` with
  provenance = model + base_url, semgrep version, joern fingerprint, git
  rev/dirty, sha of both judge scripts, sha of every `analysis/joern/*.sc`
  + `analysis/rules/*.yml` + the deterministic scripts (the ENGINE
  fingerprint), and per target `tree_sha` + record-level shas of chains /
  snippets / entrypoint snippets. v1 flat files are read transparently and
  migrated on write; entries for unregistered targets are pruned with a
  log line. Artifact hashes are computed over JSON **records**, not raw
  bytes — joern writes `[INFO]` lines to the same stdout.
- **Every FAIL names its cause**: MODEL_DRIFT / CODE_CHANGED /
  SNIPPET_CHANGED / ENGINE_CHANGED / JUDGE_CHANGED, else REAL_REGRESSION.
  `REAL_REGRESSION` is reserved for recall/FP failures — a budget overrun
  or a missing measurement is not a quality regression.
- **Token budget compares against the previous batch of the same shape**,
  not the frozen judge baseline (one call per chain vs a full
  investigation are not comparable). Confirmed rate is compared against
  the frozen baseline.
- **New dimensions are opt-in** (`--max-token-delta`, `--min-confirmed-rate`,
  `--forbid-leak`); every unmeasurable dimension prints SKIP instead of
  failing.

Still open: re-pinning the judge baseline (needs an LLM budget — see
PROGRESS.md). The frozen numbers date from 2026-08/09 and are not
reproducible from the current tree (targets pruned per D18 live only in
git history).

## Non-HTTP targets (2026-10-31)

### D17. Securities-industry non-HTTP targets: language/scenario pairs by industry reality, `entrypoint.route` as trigger descriptor

Gap: all existing targets are HTTP applications; the taxonomy had no
coverage of the non-HTTP services that securities/IB firms actually
develop and expose (the user works at one).

Decisions:
- **Forms**: message-queue/file-drop workers and FIX-style TCP command
  gateways — the two families that are both commonly self-developed AND
  externally exposed in a securities firm. Rejected with evidence:
  exchange-native binary feed handlers (ITCH/OUCH/STEP) are C++-only in
  practice and C++ is not in the language set; CLI tools are not
  externally exposed; generic file-ingestion daemons are not something
  these firms typically self-develop as exposed services (the securities
  variant — clearing/reconciliation pipelines — IS, and was kept).
- **Language↔scenario pairing by industry reality, not one-per-language**:
  FIX gateways in Java (+ C# per the original mirror plan — the C# mirror
  was later removed for engine reasons, D18); clearing/reconciliation
  workers in Python + Perl (data-pipeline lingua franca + legacy ops
  estate). **JS/TS deliberately has no non-HTTP target** — Node's role in
  securities firms is the web/API tier (already covered by
  js-ts-express); forcing it would be the equivalent of writing a web app
  in C++.
- **Schema**: `ground_truth.json` keeps its existing shape; only
  `entrypoint.route`'s VALUE becomes a trigger descriptor — `MSG <subject>`
  / `CMD <command>` / `FILE <kind>`. No new fields, judge compatibility
  preserved (matching keys on file+function).
- **Dispatch must be registry-shaped** (`router.register("D", handler)` /
  `HANDLERS["D"] = fn` / `subscribe(subject, fn)`), never a switch, so
  tree-sitter and Joern can both see the entrypoints (AGENTS.md records
  the convention).
- **Mapper support**: `scripts/repo_map.py` extracts the registration
  calls into the routes table (`method` MSG/CMD/FILE, extra `kind` key —
  HTTP routes are unaffected).
- **Not done (deferred)**: registering the non-HTTP targets in the agent
  batch/baseline (same "generate first, register later" path perl-cgi
  took); `compare_repo_maps.py --check` and the planner's route coverage
  still assume HTTP-shaped routes (documented in LIMITATIONS.md §4).

Current non-HTTP targets: `java-fix-gateway`, `python-clearing-worker`,
`perl-clearing-worker` (perl keeps its no-engine tier-3 degraded-mode
role). 17 vulnerable + 5 safe entries each, same taxonomy as the HTTP
targets.

## Language coverage (2026-09-14)

### D10. Languages without engine frontends (Perl): degraded agent-only mode

Gap: the benchmark may need targets in languages lacking a Semgrep
grammar, a Joern frontend, or both. Verified 2026-09-14: Semgrep has no
Perl grammar at all; Joern has no Perl frontend; tree-sitter-language-pack
bundles a perl grammar. Perl is tier-3: neither engine can see it —
A-class screening dies at `ensure_cpg` and the B-class worker at
`get_forward_slice`.

Decision: **design only, no code yet** — for tier-3 languages, a degraded
agent-only mode: (1) a per-language heuristic sink scanner emitting the
exact `sinks.json` contract (`semgrep_to_sinks.py` output shape), swapped
in via a per-target `engines` / `sink_detector` config key; (2) the
tree-sitter repo map as the only structural index (register perl in
`scripts/repo_map.py`); (3) A-class investigation seeded from sink
records with `search_code`/`read_function` grep-relay (today: the
tracer's read_file/search_code directives, D19); (4) a no-joern
`get_forward_slice` fallback (repo-map symbols + import graph + grep) for
the B-class worker, whose planner is already Joern-free; (5) metrics
tier-labelled and never compared against full-pipeline targets. Chosen
over transpiling Perl to a supported language (semantic chasm), over
writing a Joern Perl frontend (cost far exceeds benchmark value), and
over Semgrep `--lang generic` (no stronger than the regex scanner it
would replace). Full design: `docs/perl-degraded-mode-design.md`.

## Decided against / deferred

- **CFG-dominance checks for sanitizers / TOCTOU** (guard dominates sink;
  check-then-act without lock): high implementation cost, high misjudgment
  risk, and these semantic calls are exactly what the LLM layer is good at.
  Deferred.
- **Forward dataflow from sources to discover new sinks without Semgrep**:
  widens the false-positive surface and conflicts with the current
  architecture (Semgrep is the sink oracle, Joern confirms). Only revisit if
  Joern is ever used as a standalone scanner.
- **Deduping Semgrep intermediate-call noise** (e.g. `db.query` inside
  `userService.js` forwarding to `pool.query`): harmless noise, lowest
  priority. If ever done, filter calls whose body merely forwards to another
  flagged sink.
- **Forward script name-based sink tagging**: keep for display only; Semgrep
  shape-aware rules remain the sink oracle. No change.
- **New source kinds (file uploads, websocket/CLI inputs)**: out of scope for
  the web-only taxonomy.

## Archived decisions (full text removed 2026-11-01 for cleanliness)

One-liners so references elsewhere stay resolvable; full texts in git
history (revisions of this file before 2026-11-01).

- **D1. Route-parameter taint sources** — implemented 2026-07;
  per-language handler-param sources live in `taint_confirm.sc`.
- **D2. Name-first sink matching** — implemented 2026-07; ±3-line window
  with name ranking in `taint_confirm.sc` / `backward_from_sinks.sc`.
- **D3. Chain-level confirmation report** — implemented 2026-07;
  `CHAINS_JSON` side output + `scripts/chain_report.py`.
- **D4. Flow dedup by (entrypoint × sink), cap 3** — implemented 2026-07.
- **D5. JS import-binding call-edge repair** — resolved 2026-07 on the
  chain side (js A recall 9/10 → 10/10); the module-variable DFG gap in
  `taint_confirm.sc` remains open (LIMITATIONS.md §3).
- **D6. Write-sites attached to chain snippets** — DROPPED 2026-09-10:
  the A-class agent covers store sites at runtime; kept here so it isn't
  re-proposed.
- **D7. C# name/source-text call-site fallback** — resolved 2026-07
  (csharp recall 8/10 → 10/10); the dormant C# branches remain in the
  joern scripts as generic tooling (kept per D18). Moot for benchmarking
  after D18.
- **D8/D9. JSP transpile-to-Java + pipeline wiring** — superseded
  2026-09-05: jsp-legacy and the transpiler were removed; the dormant
  `out.print` rule branch remains in `sinks-java.yml` (inert for the
  remaining targets).
- **D11. Enterprise-grade pilot target** — target user-deleted 2026-10;
  its live residue is the no-marker rule (generalized by D15).
- **D12. Entrypoint detection by directory + rule arity fixes** —
  implemented 2026-09; the `(routes|api)/.*\.py$` convention and the
  multi-arg eval/yaml.load patterns live in the rules and joern scripts.
- **D13. Documentation consolidation (one markdown per role)** —
  implemented 2026-09; still governs this repo's doc layout.
- **D14. Agent productization first; self-evolution deferred** —
  implemented; the current sequencing lives in `plan.md` (M9 done →
  M14.1 next).
