# Decisions

Optimization decisions for the taint-confirmation pipeline, derived from
`analysis/LIMITATIONS.md` (2026-07). Ordered by cost/benefit; each entry
states the decision and the rationale. See `PROGRESS.md` for execution order.

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
