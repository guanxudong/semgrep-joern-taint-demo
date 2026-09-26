# Decisions

Optimization decisions for the taint-confirmation pipeline, derived from
`analysis/LIMITATIONS.md` (2026-07). Ordered by cost/benefit; each entry
states the decision and the rationale. See `PROGRESS.md` for execution order.

> **2026-09-05: D8/D9 superseded.** The jsp-legacy target and
> `scripts/jsp_to_java.py` were removed from the repo by user decision
> (recoverable from git history). D8/D9 below are kept as historical
> record; their engine-side traces (the `out.print` rule branch,
> `_jspService` entrypoint detection, `_jsp.java→.jsp` scorer
> normalization) remain dormant and harmless for the 4 remaining targets.

## Target coverage (2026-07)

### D8. JSP support via transpile-to-Java

Gap: legacy JSP applications are outside the pipeline — neither Semgrep nor
Joern has a JSP frontend (confirmed on joern 4.0.566: no JSP frontend
exists), so a scriptlet-style JSP target could not be benchmarked at all.

Decision: transpile, don't extend. `scripts/jsp_to_java.py` (stdlib only,
deterministic) converts `targets/jsp-legacy/pages/*.jsp` into plain-Java
servlet-style classes (Jasper-style `_jspService` methods) under the
gitignored `workspace/jsp-java/`, and the ENTIRE java pipeline
(`analysis/rules/sinks-java.yml`, javasrc2cpg via joern-parse, the joern
.sc scripts) runs on the generated tree unchanged. Chosen over Semgrep
generic-mode pattern matching (no dataflow, no call graph — would only
exercise half the pipeline) and over waiting for a Joern JSP frontend
(not on any roadmap we can see). Rationale: full reuse of the java rules
and joern scripts with zero pipeline changes; the transpilation is
line-preserving and records a per-file offset in
`workspace/jsp-java/manifest.json`, so findings map back to exact JSP
lines. Known cost: the return-based java xss sink rule did not match
`out.print(...)` — resolved by D9.

### D9. JSP pipeline wiring (out.print sink, _jspService entrypoints)

Gap: D8's generated tree parses and scans, but three pipeline pieces were
still Spring-shaped: the xss rule only matched `return <html> + x`, the
joern scripts only recognized `@*Mapping` entrypoints, and the LLM judges
matched ground truth on CPG file names (`pages/X_jsp.java` vs `X.jsp`).

Decision: minimal unions, no forks. (1) `java-sink-xss` gained an
`out.print(<... $HTML + $X ...>)` alternative under the SAME HTML
metavariable guard, and `print` joined the java sink-name tables (the CPG
call name of `out.print` is `print`); java-spring semgrep output is
byte-identical before/after. (2) All five joern scripts union JSP
entrypoints `cpg.method.nameExact("_jspService")` in `pages/*_jsp.java`
into the java case — a pure union, inert for the other targets (no
`*_jsp.java` files there) — with the route label derived by filename
convention (`pages/X_jsp.java` → `"/X.jsp"`, quoted so the judge's
route-suffix matching keeps working). Chosen over reading
`workspace/jsp-java/manifest.json` in the scripts: the convention is
equivalent and adds no env vars. (3) Both LLM judges normalize
`X_jsp.java` → `X.jsp` when comparing files, and the sink judge treats
`_jspService` as non-discriminating (every page shares it) by requiring
the route label to match too — otherwise any judged sqli chain would
match the safe sqli sample. `taint_confirm.sc` needed no change:
`request.getParameter` was already a java source and flow attribution is
file/line-range based. Result: A 10/10, B 7/7, 0 safe FPs (PROGRESS.md).

## Benchmark realism (2026-09-15)

### D11. Enterprise-grade pilot target, no in-source vuln markers

Gap: the four small targets (~500 LOC, one vuln per handler, `VULN:`/`SAFE:`
comments above every entry) invite overfitting — vuln density is ~100% of
handlers, chains are 1-2 hops, and the markers leak into the agent's
read/search tool output (mitigated only by GT-tag stripping, which itself
has had bugs).

Decision: build `targets/python-flask-enterprise/` (pilot language chosen
by the user) as a layered enterprise-style app with deep chains (up to 5
hops), decorator-gated endpoints, inconsistent sanitizer usage, and 11
near-miss SAFE mimics; and **drop the `VULN:`/`SAFE:` comment convention
for this target** — ground truth lives only in `ground_truth.json` +
`GROUND_TRUTH.md`. ~~The small targets keep their markers~~ (superseded
by D15 on 2026-09-26: markers retired everywhere).
External open-source validation repos (WebGoat/JuiceShop-style) were
considered and deferred to a later phase — pilot first, then measure.

### D12. Entrypoint detection by directory, rule arity fixes

Gap (found by the D11 pilot): joern python entrypoint detection matched
only `routes/*.py`, so the enterprise target's `api/` layout produced zero
entrypoints and every chain came out NO_CHAIN; and `sinks-python.yml`
patterns `eval($X)` / `yaml.load($D)` missed the realistic multi-arg forms
`eval(expr, globals, locals)` / `yaml.load(data, Loader=...)`.

Decision: widen the detection regex to `(routes|api)/.*\.py$` in the six
joern scripts (directory convention documented, cheap, zero change for the
existing targets — verified identical entrypoint extraction on
python-flask), and add `...` to the eval/exec/yaml.load patterns. Chosen
over renaming the target's `api/` to `routes/` (the layout difference is
part of the realism test) and over full decorator-based entrypoint
detection (more robust but a bigger change; revisit if a future target
puts routes elsewhere).

## Answer-leak hardening + new-language targets (2026-09-26)

### D15. No in-source markers anywhere; new PHP (tier-1) and Perl (tier-3) targets

Gap: although the LLM judges and agent tool layer strip `VULN:`/`SAFE:`
marker comments (`_GT_TAG` regex in `llm_judge_sink_chains.py`,
`llm_judge_entrypoints.py`, `sast_agent/investigator.py`), the stripping
is path-dependent and the four small targets also carried *descriptive*
spoiler comments ("Sink: executes a SQL string...", "No validation of
amount sign -> negative amount steals money", "attacker fires many
concurrent requests here") that no stripping rule covered — any read of
the raw source handed the LLM the answers.

Decision (user): retire the in-source marker convention in ALL targets
(supersedes the "small targets keep their markers" clause of D11) and
scrub every spoiler comment — marker lines deleted, flaw-explaining
comments deleted or reworded to neutral functional descriptions (~100
marker lines + ~50 spoiler comments across 64 files; code, identifiers,
and ground truth untouched). The `_GT_TAG` stripping machinery stays as
harmless defense-in-depth. Suggestive identifiers (`query_unsafe` etc.)
were kept because ground truth references them; renaming is only allowed
together with a ground-truth update (recorded in AGENTS.md).

Same decision round: two new targets for engine-coverage testing —
`targets/php-laravel/` (Laravel-style, 22-entry mirror of the small
targets, `php-` ids; Semgrep GA + Joern php2cpg, so tier-1 full-pipeline
with a weaker frontend; corrects the assumption that Joern lacks PHP —
php2cpg exists but needs a PHP runtime) and `targets/perl-mojo/`
(Mojolicious-style, 22-entry mirror, `pl-` ids; no Semgrep grammar, no
Joern frontend — the tier-3 no-engine degraded-mode case of D10). Both
follow the no-marker rule from birth and use neutral identifiers (safe
variants named `searchV2`/`search_prepared` etc., not `*_safe`). Pipeline
registration (`config.py` TARGETS, `run_baseline.py`, `sinks-php.yml`,
`.sc` PHP branches, `perl_sinks.py`, repo_map perl/php support, `engines`
flags) is deliberately NOT done yet — that is the D10 §6 integration work.

## Roadmap (2026-09-23)

### D14. Agent productization first; self-evolution deferred

Gap: plan.md carried two orderings — the M9–M13 ROI sequence (benchmark-
at-ceiling capability work, including the self-evolution class M10/M12)
and the M14 productization candidates — with no single priority.

Decision (user): make AI SAST agent productization the main line —
Phase 1: M14.1 unified orchestrator + funnel report → M14.3 enterprise
full validation → M14.2 tri-state batch judge + model tiering → M9
drill-down mechanization (target list from M14.3's failure attribution)
→ M11 knowledge base. Defer the self-evolution class to Phase 2: M10
rule self-evolution, M12 improvement loop, M13.1 canary guardrail — all
gated on M14.3's real failure signals. M13.2 model-drift monitoring is
neither deferred nor scheduled; pull it forward with baseline re-pinning
needs. Rationale: the benchmark is at ceiling on the four small targets;
what the project lacks is a runnable, measurable, affordable agent on
real-shaped code — and self-evolution without real failure signals would
hill-climb into overfitting the small targets.

## Documentation (2026-09-23)

### D13. Documentation consolidation: one file per role

Gap: the repo root carried six markdown files with overlapping scope, and
the closed M0–M8 spec (`AGENT_MVP_PLAN.md`) sat beside living documents —
its §10 future-work partially duplicated `plan.md`, and its header still
claimed four targets.

Decision: keep exactly one markdown per role — `README.md` (human entry),
`AGENTS.md` (agent guidance/pointers), `plan.md` (roadmap), `PROGRESS.md`
(status log), `DECISIONS.md` (decision log), `analysis/LIMITATIONS.md`
(known gaps + live agent/LLM-layer backlog, §4), `agent/HANDOFF.md`
(agent-subsystem operations). The closed spec moved to
`docs/AGENT_MVP_PLAN.md` with a CLOSED banner; its §10 items not covered
by plan.md M9–M13 (production no-GT operations, CPG platformization)
moved into plan.md's unscheduled section (cross-scan memory stays
rejected per `docs/why-not-agent-memory.md`). Problem inventory lives in
LIMITATIONS.md, scheduling in plan.md — cross-referenced, not merged.

## Language coverage (2026-09-14)

### D10. Languages without engine frontends (Perl): degraded agent-only mode

Gap: the benchmark may need targets in languages lacking a Semgrep grammar,
a Joern frontend, or both. Verified 2026-09-14: Semgrep needs a per-language
grammar (PHP is GA with cross-function dataflow; Perl is absent even from
the experimental list); Joern actually ships php2cpg (`--language PHP`,
backed by PHP-Parser and a local PHP runtime) but has no Perl frontend;
tree-sitter-language-pack bundles both php and perl grammars. So PHP is a
tier-1 candidate (full pipeline feasible — not scheduled), while Perl is
tier-3: neither engine can see it — A-class screening dies at
`ensure_cpg` and the B-class worker at `get_forward_slice`.

Decision: **design only, no code yet** — for tier-3 languages, a degraded
agent-only mode: (1) a per-language heuristic sink scanner emitting the exact
`sinks.json` contract (`semgrep_to_sinks.py:39-47`), swapped in via a
per-target `engines` / `sink_detector` config key; (2) the tree-sitter repo
map as the only structural index (register perl in `scripts/repo_map.py`);
(3) A-class investigation seeded from sink records with
`search_code`/`read_function` grep-relay (the `joern_query` manual-relay
hint turned primary); (4) a no-joern `get_forward_slice` fallback (repo-map
symbols + import graph + grep) for the B-class worker, whose planner is
already Joern-free; (5) metrics tier-labelled and never compared against
full-pipeline targets. Chosen over transpiling Perl to a supported language
(semantic chasm — sigils, scalar/list context, magic variables; and the far
simpler 1:1 JSP transpiler itself was removed 2026-09-05), over writing a
Joern Perl frontend (cost far exceeds benchmark value), and over Semgrep
`--lang generic` (line-based, no AST — no stronger than the regex scanner it
would replace). Full design: `docs/perl-degraded-mode-design.md`.

## Do now (small change, direct recall gain) — all implemented 2026-07

### D1. Add route-parameter taint sources (implemented, broadened)

Gap: `GET /users/<int:user_id>` binds input to the handler argument, never
touching `request.*`; flows from `get_user` / `delete_user` are missed.

Decision: in `taint_confirm.sc`, treat parameters of handlers whose route
contains `<...>` as sources — mirrors the existing Spring `@PathVariable`
handling. Single-script change.

Implemented broader than the original Flask-only scope, per-language in
`taint_confirm.sc`'s `sources`:

- python: handler params of routes with `<...>` (Flask) or `{...}` (FastAPI)
  placeholders; `request.get_json`/`view_args` accessor calls. Django URLconf
  path params remain invisible (not decorator-based) — still a gap.
- java: Spring `@RequestParam/@RequestBody/@RequestHeader/@PathVariable` plus
  `@ModelAttribute/@RequestPart` and JAX-RS `@PathParam/@QueryParam/@FormParam/
  @HeaderParam/@BeanParam`; `getPathInfo`/`getCookies` accessor calls.
- js: Express `req.*`, Koa `ctx.*`/`ctx.request.*`, Fastify/Hapi `request.*`.
- csharp: `Request.*` accessors + all controller action params + params of any
  `[HttpGet]`-annotated action (covers minimal APIs).

### D2. Match sinks by name first, not nearest line (implemented)

Gap: Semgrep line-hint off-by-one (`java-ssti-01`): the ±1-line tolerance
picked `new Configuration(...)` instead of the tainted `new Template(...)`
one line below.

Decision: in `taint_confirm.sc`, within a ±N line window around the Semgrep
hint, filter candidate calls by sink *name* first and pick the nearest
matching one; fall back to nearest-line only when no name matches in the
window.

Implemented in both `taint_confirm.sc` and `backward_from_sinks.sc`
(identical matching): ±3 window; name match ranked name < methodFullName
(simple name, `:signature` suffix stripped) < `new X(...)` code, so
constructor sinks (`<init>` calls) match by type name and an assignment
operator whose code mentions `new X` never beats the real constructor call.
The per-language sink name tables were aligned with `analysis/rules/`
(added e.g. `Template`, `FileInputStream`, `parse`, `send_file`,
`XMLParser`, `spawnSync`, `createReadStream`, `deserialize`) and synced
across all three Joern scripts.

### D3. Chain-level confirmation report (implemented)

Gap: confirmation is reported per sink, but the LLM layer judges per
entrypoint->sink chain.

Decision: join `backward_from_sinks.sc` chains with `taint_confirm.sc` flows
on (route, sink) and emit CONFIRMED/UNCONFIRMED per chain. Pure
post-processing of existing outputs.

Implemented: `backward_from_sinks.sc` gained a machine-readable JSONL side
output (`CHAINS_JSON=<path>`), new `scripts/chain_report.py` joins it with
the taint JSONL on (sink file+line) and attributes flows to chains by
entrypoint fullName (JS: route label, or nested-lambda prefix of the
entrypoint). Output: one JSON object per entrypoint->sink chain with
CONFIRMED / UNCONFIRMED / NO_CHAIN.

### D4. Dedup flows by (entrypoint x sink), cap per entry (implemented)

Gap: signature-based dedup plus a global cap of 5 lets duplicate paths crowd
out distinct routes (4 admin-DELETE dups filled the list at `db/index.js:13`).

Decision: dedup keyed on (entrypoint, sink); keep at least 1 flow per
entrypoint; cap at 3 flows per entry instead of 5 per sink. Post-processing
only, no Joern change.

Implemented in `taint_confirm.sc`'s emission stage (output post-processing,
no dataflow-query change): signature dedup kept, global `take(5)` replaced
by a cap of 3 flows per `source_method` (entrypoint).

## Do later (medium effort)

### D5. Jump-on-Field for JS module-level variables only

Gap: `js-sqli-02` — module-level `let pendingName` written by `stageName`,
read by `findStaged`; flow dies at the module-variable store/load across
files.

Decision: when a backward DFG walk hits a module-variable read, manually jump
to all writes of the same variable and continue from each RHS. Scope it
strictly to cross-file module variables — do NOT build a general-purpose
traversal (mostly redundant with `reachableByFlows`).

**RESOLVED (2026-07, chain side):** the NO_CHAIN root cause turned out to be
in the CALL graph, not the DFG — jssrc2cpg resolves require-imported calls
(`userService.findStaged(...)`) to GHOST methods in the caller's own file
(`routes/users.js::program:findStaged`, external=true), leaving the real
method in the required module with zero incoming CALL edges. Implemented an
import-binding call-edge repair in `backward_from_sinks.sc` and
`extract_chain_snippets.sc`: a call site `recv.name(...)` with an external
callee counts as a caller of the real method `m` when `recv` is an import
binding (IMPORT nodes) in the call's file whose module path resolves to
`m`'s file. Scoped to `lang == "js"` as decided. Result: js A recall 9/10 →
10/10. The module-variable DATAFLOW gap in `taint_confirm.sc` (DFG still
dies at the module-var store/load) remains open.

### D6. Attach write sites to chain snippets

Gap: backward chains include `find_staged` / `query_unsafe` but not the
sibling `stage_name` call that stores the taint; the LLM must infer the store.

Decision: for each field/variable appearing in a chain, append the source of
all its write call sites to the snippet. No full trace needed — store-site
source only.

**Status (2026-09-10): DROPPED — the agent covers it, and that's the better
method here.** The M3 drill-down playbook (AGENT_MVP_PLAN.md §6A) closes the
gap at runtime: `search_code(var)` finds the store sites, and the three
store-side targets (js-sqli-02, cs-cmdi-02, cs-path-traversal-01) all reach
vuln=True LIKELY 0.95 with the write sites cited as violation-free evidence
refs — benchmark recall sits at the 10/10 ceiling with zero SAFE FPs. The
mechanical version would save tokens but change no verdict, and per the
project principle (AI SAST: when the LLM already covers a gap well,
engine-side machinery must justify itself by effect, not elegance) it
doesn't. Recorded here so it isn't re-proposed.

### D7. Name-based call-site fallback for C# (LOW_CONFIDENCE)

Gap: C# flows crossing into `Services/` stay UNCONFIRMED because
csharpsrc2cpg drops the CALL edges; waiting for an upstream fix is not
realistic.

Decision: fall back to `cpg.call.name("<methodName>")` traversal when
resolved `.caller` edges are missing. Accept same-name collisions, but mark
anything confirmed this way LOW_CONFIDENCE rather than CONFIRMED. Do NOT
tune Semgrep rules to force results — this is a frontend limitation.

**RESOLVED (2026-07, chain side):** the gap was narrower than expected —
csharpsrc2cpg drops the call NODE entirely when `_svc.Method(...)` is nested
inside another call (`Ok(_svc.Method())`), so even name-based call
traversal finds nothing. Implemented a source-text fallback in
`backward_from_sinks.sc` / `extract_chain_snippets.sc`: a controller method
counts as a caller of service method `m` when (a) its source text contains
`".<mname>("` and (b) its declaring type has a field/property of `m`'s
declaring type. Edges are logged as `D7 LOW_CONFIDENCE` on stderr. 10 edges
synthesized, all verified semantically correct (including safe variants
mapping to safe methods only). Result: csharp A recall 8/10 → 10/10. The
`taint_confirm.sc` dataflow side (cross-file flows still UNCONFIRMED)
remains open.

Update (2026-07): the same nested-call gap bites the FORWARD direction —
`extract_entrypoint_snippets.sc` (category-B path) missed
`_orderService.Transfer(...)` inside `Ok(...)`, starving the LLM of the
service bodies (found when the ground-truth label leak was fixed and cs B
honestly dropped to 5/7). Added the mirror-image fallback: a Services/Data
method counts as a callee of a controller method when the controller's
source contains `".<name>("` and holds a field of the callee's declaring
type. cs B back to 7/7 without label leakage.

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
