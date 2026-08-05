# Restlet → CHF migration — document index

**This tree is ~320k tokens. Never load it, and never load a whole phase doc "to see what's
there."** Start from the task table below: it names the *set* of files a given job needs, and
nothing else. Every set is sized to fit comfortably in context alongside the code.

| | |
|---|---|
| Where the plan lives | [plan.md](plan.md) — phase status, risk register, expected divergences |
| What is locked | [decisions.md](decisions.md#locked-decisions) |
| Current step | **5d-1c — the flip.** [spec](phase-5d-1.md) · [as-built so far](phase-5d-1-asbuilt.md) |

---

## Load these, for this job

The right-hand column is the **complete** reading list. If something is missing from it, that is a
bug in this table — fix the table rather than reading the whole tree.

| I am… | Load (≈ tokens) |
|---|---|
| **implementing 5d-1c (the flip)** | [phase-5d-1.md](phase-5d-1.md) 11k + [plan.md#expected-divergences-at-the-flip](plan.md#expected-divergences-at-the-flip) 5k = **~16k**. The as-built and research files are *reference* — open a section only when the spec cites it |
| **planning 5d-2 (the deletion)** | [phase-5d-1-asbuilt.md#handed-to-5d-2](phase-5d-1-asbuilt.md#handed-to-5d-2) + [inventory.md#12](inventory.md#12-deletion-checklist-final-state) + [inventory.md#9](inventory.md#9-guice-bindings-that-changedie) = **~7k** |
| **planning phase 6 / 7 / 8** | [plan.md](plan.md) 14k + [inventory.md](inventory.md) 5k = **~19k** |
| **writing a new CHF handler** | the [conversion template](phase-5-oauth2.md#the-conversion-template-applies-to-every-5a5b5c-handler) + the two or three [chf-patterns](chf-patterns.md) sections it names — **never the whole file** |
| **fixing `openam-http`** | [openam-http-framework.md](openam-http-framework.md) F1–F5 + [chf-patterns §14](chf-patterns.md#14-framework-defects-fix-them-dont-pattern-around-them-2026-07-21) |
| **answering "what did Restlet do here?"** | the `-asbuilt.md` of the phase that ported it — every live-Restlet measurement lives there. See [the oracle record](#the-oracle-record) |
| **reviewing a spec before implementation** | that phase's `phase-X.md` alone. Research and as-built are not review inputs |

## How to read these docs

1. **Index the target first** — cheap (~300 bytes), gives you the line ranges:
   ```
   grep -n '^#\{1,2\} ' docs/migration/restlet/<file>.md
   ```
2. **Read only that range** (`Read` with `offset`/`limit`).
3. **Delegate wide reads.** A question spanning several docs goes to a subagent — it burns its own
   context and returns the conclusion.
4. **Keep build output out of context.** Redirect to a file, grep the file:
   ```
   mvn -q -am -pl <module> test > build.log 2>&1; grep -E 'ERROR|FAIL|Tests run' build.log | head -40
   ```

<a id="the-oracle-record"></a>
## The oracle record — why `-asbuilt.md` files are not deletable

The live Restlet stack is the only answer to *"what does OpenAM do today"*, and **it dies at 5d-1c**
([risk #20](plan.md#risk-register-behavioral-compatibility)). Every value ever measured against it —
the 5-E / 5-E2 / 5-E3 / 5-E4 / 5-E5 gate rows, the live smokes, the divergence bytes — lives in an
`-asbuilt.md` file. Those numbers cannot be re-derived after the flip, so:

- **never delete a measured value** from an as-built, and never "tidy" one into a summary;
- a phase's *process* (checklists, verification criteria, execution steps) is recoverable from git
  and is deleted once the phase lands — which is why completed phases no longer carry it;
- when a measurement refutes a prediction, **the measurement replaces it.** Do not keep both.

## Document set

Each phase is up to three files: **`phase-X.md`** the spec (design decisions, what is still owed),
**`phase-X-research.md`** the background that drove it (read once), **`phase-X-asbuilt.md`** what
landed plus the oracle rows.

### Cross-cutting — relevant in every phase

| Doc | Size | Read it for |
|---|---|---|
| [decisions.md](decisions.md) | 7k | The decision record + the CHF cleanup backlog. Short — read it whole |
| [plan.md](plan.md) | 14k | Phase status, the global behavioural risk register, **the expected divergences at the flip** |
| [chf-patterns.md](chf-patterns.md) | 22k | 23 numbered CHF findings. **Always one section, never the file** |
| [inventory.md](inventory.md) | 5k | What still imports Restlet, route tables, the deletion checklist |
| [openam-http-framework.md](openam-http-framework.md) | 18k | Fixes we made to `openam-http` itself (F1–F5) |
| [phase-5-oauth2.md](phase-5-oauth2.md) | 17k | Phase 5 umbrella — route table, conversion template |

### Phase documents

| Phase | Spec | Research | As-built | State |
|---|---|---|---|---|
| 2 — `/xacml` | [4k](phase-2-xacml.md) | — | — | done |
| 2 — XACML e2e + IT | [8k](phase-2-integration-tests.md) | — | — | done |
| 3 — sizing | — | [5k](phase-3-research.md) | — | done |
| 3a — `OAuth2Request` | [9k](phase-3a-oauth2request.md) | — | — | done |
| 3b — collaborators | [12k](phase-3b-collaborators.md) | — | — | done |
| 3c-1 — renderer | [14k](phase-3c-1-renderer.md) | — | — | done |
| 3c-2 — error layer | [21k](phase-3c-2-error-layer.md) | — | — | done |
| 3d — audit | [14k](phase-3d-audit.md) | — | — | done |
| 4 — `/uma` | [16k](phase-4-uma.md) | — | — | done |
| 5a-1 — `/access_token` | [11k](phase-5a-1.md) | — | — | done |
| 5a-2 — 9 JSON endpoints | [10k](phase-5a-2.md) | — | — | done |
| 5b-1 — `/authorize` | [6k](phase-5b-1.md) | [5k](phase-5b-1-research.md) | [16k](phase-5b-1-asbuilt.md) | done |
| 5b-2 — device / checkSession / endSession | [5k](phase-5b-2.md) | [7k](phase-5b-2-research.md) | [8k](phase-5b-2-asbuilt.md) | done |
| 5c — `/oauth2/resource_set` | [10k](phase-5c.md) | [10k](phase-5c-research.md) | [16k](phase-5c-asbuilt.md) | done |
| **5d-1 — the flip** | **[11k](phase-5d-1.md)** | [8k](phase-5d-1-research.md) | [10k](phase-5d-1-asbuilt.md) | **5-E5 / 5d-1a / 5d-1b done · 5d-1c pending** |

Phases 6–8 (WebFinger + stragglers, outbound client, final deletion) have no doc of their own — they
live in [plan.md](plan.md#phase-6--webfinger--stragglers).

---

## Topic router

### Ground rules and process
| I need… | Go to |
|---|---|
| What I'm not allowed to change | [decisions.md#locked-decisions](decisions.md#locked-decisions) |
| How a route gets flipped Restlet↔CHF | [decisions.md#cutover-lever](decisions.md#cutover-lever) |
| Behaviour that *intentionally* changes at the flip | [decisions.md](decisions.md#phase-3c--behaviour-changes-that-land-at-the-phase-5d-flip-locked-2026-07-17) |
| **What may legitimately differ after the flip** | [plan.md#expected-divergences-at-the-flip](plan.md#expected-divergences-at-the-flip) |
| Deferred cleanups (tracked, not blocking) | [decisions.md#chf-cleanup-backlog](decisions.md#chf-cleanup-backlog) |
| The per-phase verification workflow | [plan.md#verification-workflow-every-phase](plan.md#verification-workflow-every-phase) |
| How parity is proven before deleting Restlet | [chf-patterns §13](chf-patterns.md#13-the-3-way-golden-oracle-phase-3c--how-parity-survives-restlets-deletion) |
| Policy: fix `openam-http`, don't work around it | [chf-patterns §14](chf-patterns.md#14-framework-defects-fix-them-dont-pattern-around-them-2026-07-21) |

### Writing a CHF handler
| I need… | Go to |
|---|---|
| The endpoint conversion template | [phase-5-oauth2.md](phase-5-oauth2.md#the-conversion-template-applies-to-every-5a5b5c-handler) |
| Registering routes (`HttpRouteProvider`) | [chf-patterns §1](chf-patterns.md#1-httprouteprovider-spi) |
| `Endpoints.from` semantics | [chf-patterns §2](chf-patterns.md#2-endpointsfrom--semantics-that-matter) |
| Realm routing wiring | [chf-patterns §3](chf-patterns.md#3-realm-routing-wiring-mirrors-json) |
| Filter ordering / `Handlers.chainOf` | [chf-patterns §4](chf-patterns.md#4-named-filters-and-handlerschainof-ordering) |
| Handler test scaffolding | [chf-patterns §5](chf-patterns.md#5-chf-handler-test-scaffolding) |
| Route-provider mechanics, no-match behaviour | [chf-patterns §23](chf-patterns.md#23-route-provider-mechanics--when-handlers-are-built-and-what-a-no-match-answers-phase-5d-1) |
| URI templates, trailing slashes, `HEAD` | [chf-patterns §22](chf-patterns.md#22-chf-uri-template-matching--trailing-slashes-variables-and-head-phase-5c-review) |

### Request / response traps
| I need… | Go to |
|---|---|
| Header & entity gotchas on CHF `Response` | [chf-patterns §6](chf-patterns.md#6-headerentity-gotchas-chf-response) |
| Parameter & body parsing | [chf-patterns §7](chf-patterns.md#7-chf-request-side-parameter--body-parsing-chfoauth2request-phase-3a) |
| Headers, locale, basic auth | [chf-patterns §8](chf-patterns.md#8-chf-request-headers-locale-and-basic-auth-phase-3a) |
| Endpoint-path derivation | [chf-patterns §9](chf-patterns.md#9-endpoint-path-derivation-across-the-realm-router-phase-3a) |
| **The URI is absolute under `HttpFrameworkServlet`** | [chf-patterns §18](chf-patterns.md#18-the-chf-request-uri-under-httpframeworkservlet-is-absolute-phase-5b-1) |
| Restlet thread-locals (`Request.getCurrent()`) | [chf-patterns §10](chf-patterns.md#10-requestgetcurrent--responsegetcurrent--restlet-thread-locals-phase-3a) |
| Conditional-request machinery | [chf-patterns §21](chf-patterns.md#21-restlets-conditional-request-machinery-phase-5c) |

### Errors, audit, security
| I need… | Go to |
|---|---|
| The error layer design | [phase-3c-2-error-layer.md#decisions](phase-3c-2-error-layer.md#decisions) |
| On a browser base, **build** errors — never throw | [chf-patterns §20](chf-patterns.md#20-on-the-browser-base-build-your-errors--never-throw-them-phase-5b-1) |
| `OAuth2Exception` → HTTP status quirks | [chf-patterns §17](chf-patterns.md#17-oauth2exception--http-status-quirks-phase-5a-2b) |
| Restlet `StatusService` CREST body for bare errors | [chf-patterns §16](chf-patterns.md#16-the-restlet-statusservice-renders-a-crest-body-for-bare-error-statuses-phase-4) |
| What the Restlet `OAuth2Filter` wrapped every resource in | [chf-patterns §19](chf-patterns.md#19-what-the-restlet-oauth2filter-did-around-every-oauth2-resource-phase-5b-1) |
| Access-audit filter shape & traps | [chf-patterns §15](chf-patterns.md#15-chf-access-audit-base-abstracthttpaccessauditfilter--shape--traps-phase-3d) |
| Security debts reproduced deliberately | [phase-5-oauth2.md](phase-5-oauth2.md#parity-preserved-security-debts--reproduce-now-fix-later-finding-7) |
| Bugs reproduced on purpose (T1–T8) | [plan.md](plan.md#post-migration-tickets--raised-by-the-port-deliberately-not-fixed-in-it) |

### Deleting Restlet
| I need… | Go to |
|---|---|
| What 5d-2 must delete, and the two same-named classes | [phase-5d-1-asbuilt.md#handed-to-5d-2](phase-5d-1-asbuilt.md#handed-to-5d-2) |
| What still imports Restlet | [inventory.md#3](inventory.md#3-restlet-imports-by-module-main-sources) |
| Entry points & request flow | [inventory.md#4](inventory.md#4-entry-points-and-request-flow) |
| Route tables | [inventory.md#5](inventory.md#5-route-tables) |
| Where Restlet leaks past the adapter layer | [inventory.md#7](inventory.md#7-coupling-analysis--where-restlet-leaks-past-the-adapter-layer) |
| Guice bindings that change or die | [inventory.md#9](inventory.md#9-guice-bindings-that-changedie) |
| Outbound Restlet clients | [inventory.md#10](inventory.md#10-outbound-restlet-clients) |
| The final deletion checklist | [inventory.md#12](inventory.md#12-deletion-checklist-final-state) |

---

## Conventions for new phase docs

- `phase-<id>.md` — **the spec.** Context, design decisions, what is still owed. **Target ≤10k
  tokens.** If it will not fit, the step is too big — split the step, the way 5a→5b→5c→5d were.
- `phase-<id>-research.md` — findings, dead ends, source archaeology. Read once, usually by a
  subagent. No size limit.
- `phase-<id>-asbuilt.md` — what landed, the gate rows, the divergences. **Append here; never
  rewrite a measured value.**

When a phase completes, its checklist, verification criteria, execution steps and discharged risks
are **deleted** — the as-built records what they produced, and git records the rest.

**Adding or splitting a doc?** Update the tables above, then run the link checker — broken markdown
anchors fail silently, so nothing else will tell you:

```
python3 docs/migration/restlet/check-links.py
```

It resolves heading-derived anchors, the explicit `<a id="...">` short ids (`#d10`, `#21b`), **and**
catches a link whose `#` has gone missing (`](d5)` instead of `](#d5)`) — a real breakage this tree
suffered during the 2026-08-05 reorganisation, invisible to every other check. Prefer an explicit
`<a id="...">` for anything linked often: heading text gets edited, short ids don't.
