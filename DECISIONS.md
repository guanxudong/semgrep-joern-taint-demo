# Decisions

Optimization decisions for the taint-confirmation pipeline, derived from
`analysis/LIMITATIONS.md` (2026-07). Ordered by cost/benefit; each entry
states the decision and the rationale. See `PROGRESS.md` for execution order.

## Do now (small change, direct recall gain)

### D1. Add Flask path parameters as taint sources

Gap: `GET /users/<int:user_id>` binds input to the handler argument, never
touching `request.*`; flows from `get_user` / `delete_user` are missed.

Decision: in `find_entrypoints.sc`, treat parameters of handlers whose route
contains `<...>` as sources — mirrors the existing Spring `@PathVariable`
handling. Single-script change.

### D2. Match sinks by name first, not nearest line

Gap: Semgrep line-hint off-by-one (`java-ssti-01`): the ±1-line tolerance
picked `new Configuration(...)` instead of the tainted `new Template(...)`
one line below.

Decision: in `taint_confirm.sc`, within a ±N line window around the Semgrep
hint, filter candidate calls by sink *name* first and pick the nearest
matching one; fall back to nearest-line only when no name matches in the
window.

### D3. Chain-level confirmation report

Gap: confirmation is reported per sink, but the LLM layer judges per
entrypoint->sink chain.

Decision: join `backward_from_sinks.sc` chains with `taint_confirm.sc` flows
on (route, sink) and emit CONFIRMED/UNCONFIRMED per chain. Pure
post-processing of existing outputs.

### D4. Dedup flows by (entrypoint x sink), cap per entry

Gap: signature-based dedup plus a global cap of 5 lets duplicate paths crowd
out distinct routes (4 admin-DELETE dups filled the list at `db/index.js:13`).

Decision: dedup keyed on (entrypoint, sink); keep at least 1 flow per
entrypoint; cap at 3 flows per entry instead of 5 per sink. Post-processing
only, no Joern change.

## Do later (medium effort)

### D5. Jump-on-Field for JS module-level variables only

Gap: `js-sqli-02` — module-level `let pendingName` written by `stageName`,
read by `findStaged`; flow dies at the module-variable store/load across
files.

Decision: when a backward DFG walk hits a module-variable read, manually jump
to all writes of the same variable and continue from each RHS. Scope it
strictly to cross-file module variables — do NOT build a general-purpose
traversal (mostly redundant with `reachableByFlows`).

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
