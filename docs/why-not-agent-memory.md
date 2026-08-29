# Why We Are Not Using Agent Memory in Our AI SAST (Yet)

**Audience:** engineering team
**Status:** team guidance / design position
**Scope:** our LLM-assisted SAST pipeline (static analyzer + LLM second-pass verifier)

---

## TL;DR

- **Agent memory is not the right tool for reducing false positives.** FP is an
  *evidence and semantics* problem, not a *recollection* problem.
- Using memory as a suppression mechanism trades false positives for **false
  negatives**, which are strictly more dangerous in a security product.
- What we should build instead is **structured, auditable, versionable state**:
  a Security Knowledge Base, Finding History, and reason-coded human feedback.
- To actually move precision and recall *right now*, we should invest in:
  **evidence collection, sanitizer/framework semantics, verification quality,
  and per-layer measurement** — not memory.

---

## 1. The proposal we are pushing back on

A common proposal when FP rate is high:

```text
FP rate is high
  ↓
Give the agent memory of past decisions
  ↓
It stops reporting things users already dismissed
  ↓
FP rate goes down
```

This causal chain does not hold. Before adopting it, we require an answer to:

> **Where exactly do our false positives come from, and which missing piece of
> evidence would memory supply?**

In most cases, memory supplies nothing that was missing.

---

## 2. Where false positives actually come from

A finding in our pipeline is produced by a chain:

```text
code
  ↓
candidate finding
  ↓
source → dataflow → sink
  ↓
LLM judgment
  ↓
is the vulnerability real?
  ↓
severity / confidence
  ↓
report
```

A false positive can originate at any stage. The main sources:

| FP source                    | Underlying problem                                  | Can memory fix it?  |
| ---------------------------- | --------------------------------------------------- | ------------------- |
| Wrong source classification  | Input is not actually attacker-controlled           | No                  |
| Wrong sink classification    | The API is not actually dangerous in context        | No                  |
| Inaccurate dataflow          | No exploitable path actually exists                 | No                  |
| Sanitizer not recognized     | Framework/custom sanitizer missing from the model   | Partially           |
| Missing framework semantics  | Spring/Django/Rails behavior not modeled            | Partially           |
| Infeasible path              | Static path is unreachable in practice              | No                  |
| Missing config/environment   | Configuration makes the vulnerability impossible    | Partially           |
| Duplicate finding            | Same issue reported multiple times                  | Yes — good fit      |
| Project-specific convention  | Project has safe wrappers/helpers                   | Yes — good fit      |
| Historical suppressions      | Team already judged this pattern safe               | Yes — good fit      |
| Wrong severity               | Issue is real but risk is misclassified             | Partially           |

Key observation:

> **The majority of precision problems are semantic analysis, program analysis,
> and evidence-gathering problems — not memory problems.**

### Taint propagation ≠ vulnerability

The most common beginner mistake in this domain is treating "a source→sink path
exists" as "a vulnerability exists". Example:

```python
cmd = request.args.get("cmd")
execute(cmd)


def execute(cmd):
    if cmd not in ALLOWED_COMMANDS:
        return
    os.system(cmd)
```

The taint is real. The vulnerability is not — there is a validation layer in
between. A scanner's real question is never *"is there a pattern that looks
like a vulnerability?"* but:

> **"Is there a real, reachable, exploitable attack path that violates a
> security property?"**

Answering that requires evidence: attacker-control of the source, effectiveness
of sanitizers, reachability, exposure of the endpoint, authorization checks,
configuration. None of that is stored in an agent's memory.

---

## 3. Why memory is the wrong mechanism

### 3.1 SAST needs evidence; memory provides experience

Suppose the agent once saw:

```python
foo.validate(input)
```

and a user told it: "this validate is a sanitizer, don't report." Stored as
memory, the next occurrence gets suppressed. Then the codebase evolves:

```python
foo.validate(input, strict=False)   # validation disabled
foo.validate(input)                 # only checks length
foo.validate(input)
dangerous_sink(other_value)         # different value reaches the sink
```

Memory still whispers "validate = safe" — and we now ship **false negatives**.
Experience has no boundary conditions; evidence does. In a security product,
an FN is far more expensive than an FP.

### 3.2 Memory is not auditable

Every suppression in a security scanner must be able to answer *"why was this
not reported?"* Free-form agent memory cannot answer that. Structured records
can.

### 3.3 Memory optimizes the metric, not the product

Suppressing previously-seen findings lowers the measured FP rate without
improving the analyzer's actual understanding. It teaches the system the
answer key instead of teaching it to reason — and it does nothing for code
that was never seen before.

---

## 4. What we build instead: structured persistent state

The legitimate need behind the memory proposal — *"a user marked this as FP;
stop showing it"* — is real, and we should serve it. But with structured,
versionable, auditable state rather than agent recollection:

```text
Security Knowledge Base
  - project-level sanitizers (e.g. SecurityUtils.escapeSql)
  - safe wrappers (e.g. DatabaseClient.querySafe)
  - framework semantics (Spring/Django/Servlet behavior)
  - project conventions

Finding History
  - stable finding fingerprint (rule + sink symbol + dataflow hash,
    NOT file+line)
  - historical verdict (valid / false positive / uncertain)
  - structured reason + evidence references
  - automatic invalidation when the enclosing function changes

Human Feedback
  - the input channel for the two stores above —
    not free text injected into prompts
```

Two hard requirements:

1. **Every suppression carries a structured reason**, e.g.:

   ```text
   [ ] Not attacker controlled
   [ ] Sanitized
   [ ] Not a real sink
   [ ] Unreachable
   [ ] Protected by authorization
   [ ] Test code
   [ ] Generated code
   [ ] Duplicate
   [ ] Compensating control
   [ ] Other
   ```

2. **Suppressions expire.** If the sink's enclosing function body changes, the
   suppression is invalidated and the finding re-enters verification.

From the user's perspective this behaves exactly like the memory proposal —
"mark it once, never see it again" — but it is auditable, expires safely, and
does not generalize into false negatives.

---

## 5. Reference architecture

```text
                 Source Code
                      │
                      ▼
            ┌───────────────────┐
            │  Static Analyzer  │  "here is a suspicious path"
            └───────────────────┘
                      │
                      ▼
              Candidate Findings
                      │
                      ▼
        ┌───────────────────────────┐
        │    Evidence Collector     │
        │  - source / sink code     │
        │  - dataflow & call graph  │
        │  - surrounding functions  │
        │  - sanitizer candidates   │
        │  - framework context      │
        │  - configuration          │
        └───────────────────────────┘
                      │
                      ▼
            ┌───────────────────┐        ┌─────────────────────────┐
            │   LLM Verifier    │◄───────│  Security Knowledge DB  │
            │ (semantic judge)  │ query  │  + Finding History      │
            └───────────────────┘        └─────────────────────────┘
                      │
             ┌────────┼─────────┐
             ▼        ▼         ▼
           Valid   Invalid   Uncertain
             │        │         │
             ▼        ▼         ▼
          Report  Suppress   Human Review
                     (with reason)
```

The LLM is positioned as a **Vulnerability Verifier / Semantic Analyzer**,
not an autonomous agent that depends on long-term memory. The knowledge DB is
queried *explicitly*; nothing is implicitly "remembered".

---

## 6. Where we focus now to improve precision & recall

Priority order (highest impact first):

| Priority | Investment                                     | Why                                                        |
| -------- | ---------------------------------------------- | ---------------------------------------------------------- |
| ★★★★★    | Evidence collection per finding                | Most FP/FN decisions fail for lack of context, not reasoning |
| ★★★★★    | Sanitizer & safe-wrapper coverage              | Largest single FP source in taint-style analysis           |
| ★★★★★    | Framework semantics (Spring/Flask/Express/ASP.NET) | Sources/sinks/routing are framework-defined             |
| ★★★★★    | LLM verification quality (reason + evidence)   | Verifier must justify verdicts, not just emit labels       |
| ★★★★☆    | Finding fingerprinting & dedup                 | Removes duplicate noise; enables Finding History           |
| ★★★★☆    | Structured feedback loop (reason-coded)        | Turns human triage into durable knowledge                  |
| ★★★☆☆    | Recall guardrails (benchmark regression gate)  | Every precision fix must be checked for FN introduction    |
| ★★☆☆☆    | Agent memory                                   | Not now; revisit only after the above are mature           |

**Golden rule:** any change that reduces FP must be evaluated for its effect
on FN on a fixed benchmark with ground truth. Precision gains that come from
suppression-like mechanisms are presumed guilty of recall loss until proven
otherwise.

---

## 7. Measure FP per layer, not as one number

A single `FP rate = FP / findings` figure hides where the problem is. Measure
a funnel instead:

```text
1000 candidates
  ↓ candidate precision            60%
600 real taint paths
  ↓ vulnerability validation       50%
300 semantically valid vulnerabilities
  ↓ dedup effectiveness
250 unique findings
```

With this breakdown, "FP is high" becomes an actionable statement like
"validation precision is 50% because sanitizers X/Y/Z are not modeled" — and
the fix is rule/semantics work, not memory.

---

## 8. When memory-like mechanisms become appropriate

We are not banning persistence forever. We are sequencing it:

1. **First** — evidence collection, semantics, verification quality, and
   per-layer measurement reach a stable baseline.
2. **Then** — structured Finding History and Security Knowledge Base absorb
   recurring human judgments, with reasons and expiry.
3. **Only then**, if a residual need exists (e.g. cross-scan workflow context,
   analyst preferences), consider narrow, structured memory — never free-form
   long-term recall in the detection path.

---

## 9. Team principles

1. **Every FP must have a diagnosed root cause** (source? sink? dataflow?
   sanitizer? framework? reachability? config? duplicate?) before any fix is
   proposed.
2. **Every suppression must carry a structured reason and evidence.**
3. **Suppressions expire when the underlying code changes.**
4. **The LLM verifies with evidence; it does not suppress from recollection.**
5. **Precision changes are gated on recall regression benchmarks.**

---

*Questions or pushback: bring a concrete FP example and walk it through the
layered taxonomy above — that conversation is always more productive than
"let's add memory".*
