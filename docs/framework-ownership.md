# Framework ownership — fix it or work around it?

Repo-wide reference. Written 2026-07-21 while planning the Restlet→CHF
[openam-http framework fixes](migration/restlet/openam-http-framework.md); coordinates verified against the
root `pom.xml` on `features/restlet-migration`, but **versions and line references drift** — re-check before
relying on an exact number.

Read this when a plan is about to design *around* a defect in framework or platform code.

## The principle

> **Find out who owns the code before you design around its bugs.**
> Open Identity Platform maintains far more of this stack than a first read suggests. A workaround shipped
> against code we own is a defect kept alive forever, paid for by every consumer that follows.

The counter-principle matters just as much: **ownership is not the same as cheapness.** Some code we own is
still expensive to change because it ships as a released artifact other projects consume. But *expensive* is
not *closed*: when a fix is general, the right move is to fix the upstream project, cut a release, and consume
it here (decided 2026-07-21). The point is to *classify deliberately*, not to fix everything and not to work
around everything.

**Classify before you cost it.** The ownership question is "which module is this file in", and the answer is
routinely a tier lower than it looks. When the Restlet migration re-ran this classification with "fix commons
and release" genuinely on the table, **two of the three defects earmarked for commons turned out to be tier 1
after all** — see [Worked examples](#worked-examples). Reaching for the expensive tier before checking the
cheap one is the most common way this goes wrong.

## Ownership map

| Tier | Coordinates | Source lives | Cost to change | Verdict |
|---|---|---|---|---|
| **1. In-tree** | `org.openidentityplatform.openam`, `…openam.jakarta`, `…openam.pmd.rules` | **this repo** — 55 modules (`pom.xml`) | an ordinary commit | **Fix it.** |
| **2. Ours, released** | `org.openidentityplatform.commons` (+ `.http-framework`, `.ui.libs`), `org.openidentityplatform.opendj`, `org.openidentityplatform` (parent), OpenICF, OpenIG | sibling OIP repositories | a release cycle **plus** a version/BOM bump here | **Fix upstream and consume the release** when the fix is general — see [Upstreaming to commons](#upstreaming-to-commons). Work around only when the defect is specific to our use, or the plan genuinely cannot wait. |
| **3. Vendored third-party** | `org.openidentityplatform.external.*` (e.g. `…external.com.iplanet.jato`) | re-published third-party | as tier 2, but nobody upstream will take a patch | Usually work around; patch only if load-bearing. |
| **4. Genuine third-party** | freemarker, jackson, netty, guava, … | upstream projects | fork or upstream PR | Work around, and **document why** so the next reader does not re-litigate it. |

Two traps this table exists to catch:

- **`openam-http` is tier 1.** `org.forgerock.openam.http.annotations` — `Endpoints`, `AnnotatedMethod`,
  `@ExceptionHandler` — is a module of this repository (`pom.xml:267`). **A `org.forgerock.*` package name
  says nothing about ownership**; most of this codebase carries ForgeRock package names and is maintained
  here. Judge by the module, never by the package.
- **The Restlet fork is tier 1 too.** `org.openidentityplatform.openam.jakarta:org.restlet` is built from
  `transform-jakarta/` (`pom.xml:336`) — which is why "remove Restlet" is a deletion we can actually perform,
  not a dependency we must wait out.

Tier 2's cost is concrete rather than theoretical: commons `http-framework:core` is **not version-pinned in
this pom at all** — it arrives through the imported `opendj-parent` BOM (`pom.xml:412-417`). That makes a
tier-2 fix a release plus a version decision here, not a commit — but it is a well-trodden path, not a wall.
See [Upstreaming to commons](#upstreaming-to-commons).

<a id="upstreaming-to-commons"></a>
## Upstreaming to commons (tier 2)

**A general defect in commons gets fixed in commons, released, and consumed here.** "It ships as an artifact"
is a cost, not a veto.

**Is the fix general?** Fix upstream if it would be a bug for *any* consumer (OpenIG, OpenDJ, OpenICF, a
third-party embedder), not just for how OpenAM happens to call it. If the behaviour is arguably correct and
only awkward for us, adapt locally instead — commons is not OpenAM's private utility library.

**How a new commons release reaches this pom.** No OpenAM pom declares a commons version: all 14
`http-framework` dependencies are version-less. The version arrives through an import chain —
`pom.xml:412-417` imports `org.openidentityplatform.opendj:opendj-parent:${opendj.version}` (`pom.xml:82`),
which imports `org.openidentityplatform.commons:parent:${commons.version}`, which manages the artifact.
Two ways to pick up a new release:

| Path | Steps | When |
|---|---|---|
| **Direct override** (preferred) | release commons → add an explicit `<dependencyManagement>` entry for the artifact in OpenAM's root pom | Normal case. A pom's own `dependencyManagement` wins over an imported BOM, so this is one entry, decoupled from the OpenDJ release train, and trivially revertible |
| **Full chain** | release commons → release `opendj-parent` with the new `commons.version` → bump `<opendj.version>` here | When several commons artifacts move together, or the next OpenDJ release is imminent anyway. Drags unrelated OpenDJ changes in with it |

**Sequencing.** The upstream release must be **out and consumed** before the dependent work merges — never
merge code here against an unreleased SNAPSHOT of a sibling project. If the phase cannot wait for the release,
work around it *and* file the upstream fix, rather than silently choosing the workaround.

**Behaviour changes need release notes, not just a fix.** A commons change lands in projects that never
reviewed it. If the fix alters bytes on the wire (charsets, encodings, status codes), say so explicitly in the
release note, with the before/after.

## How to decide

1. **Locate the module before designing anything.** `find . -name Foo.java -not -path '*/target/*'`, then read
   the `<module>` list. This takes seconds and changes the answer.
2. **Classify by tier**, not by how foreign the package name looks.
3. **Tier 1 → fix it**, as its own commit (below).
4. **Tier 2 → is the fix general?** If it would be a bug for any consumer, fix it upstream, release, and
   consume it ([Upstreaming to commons](#upstreaming-to-commons)). If it is specific to how we call the API,
   adapt locally. Either way, record the decision — and if the phase cannot wait for the release, work around
   it **and** file the upstream fix.
5. **Tier 3/4 → work around, and write down why**, so the workaround reads as a decision rather than as
   ignorance.

## Rules for fixing tier-1 framework code

- **Its own commit, with its own tests.** A shared-framework change must never ride inside a feature or
  migration commit — otherwise the migration gets blamed for a regression it merely carried, and reviewers
  cannot see the framework diff for the feature diff.
- **Characterize first if the code is untested.** Framework code that everything depends on is exactly where
  a test suite is most often absent. Pin current behaviour in tests *before* changing it, so the behaviour
  change appears as a test diff instead of an assertion in a plan document.
- **Enumerate the blast radius by grep**, in the plan, before writing code — every call site, named. Then run
  those modules' suites in verification.
- **Existing ForgeRock-origin files keep their package and CDDL header** and gain
  `Portions copyright <year> 3A Systems LLC.` The
  `org.openidentityplatform.openam.*`/no-ForgeRock-copyright convention
  ([restlet decisions.md](migration/restlet/decisions.md)) governs **new** classes only.
- **Prefer failing at wiring time over request time.** If the framework can reject a mistake when the route is
  built, it should — a deferred `UnsupportedOperationException` is worse than an unsupported feature.

## Smells that mean you are working around something you own

- A filter or wrapper that **synthesises what the framework should have emitted** (a missing body, a missing
  header, a missing status).
- A rule of the form *"every handler must remember to X"*, where the framework could enforce X once.
- A behaviour that survives only **by accident** — "this works because `getJson()` throws `IOException` on a
  non-JSON body, so we fall through". Accidents become load-bearing, then break silently.
- A framework annotation, hook or return type that is **declared but unimplemented**, worked around per-area
  instead of implemented once.
- The phrase *"if this needs fixing, it should be fixed once in \<module\>"* appearing in a plan — that
  sentence has already identified the right change; check the tier and do it.

## Worked examples

| Case | Tier | Decision |
|---|---|---|
| `AnnotatedMethod` swallows a handler-thrown exception into a bodiless 500; `@ExceptionHandler` declared but inert; `Promise` returns unimplemented | 1 (`openam-http`) | **Fixed 2026-07-22** — [openam-http-framework.md](migration/restlet/openam-http-framework.md) F1–F3, landed as four prerequisite commits with the package's first 64 tests ([as-built](migration/restlet/openam-http-framework.md#as-built)). Removed a filter rule, two risks and a "handlers must catch everything" rule from the plan that depended on them |
| `Endpoints.from` handlers returning `String` get ISO-8859-1 with no `Content-Type` | **1**, not 2 as first classified | **Fixed in-tree** — `openam-http` already declares `@Produces` (RUNTIME-retained, zero usages, never consulted), which is precisely the missing input. **Fixed 2026-07-22** — F4 in [openam-http-framework.md](migration/restlet/openam-http-framework.md). No commons release needed |
| `BaseURLProvider`'s CHF-looking `getRootURL` overload takes a **CREST** `HttpContext` that no `Endpoints.from` route can produce | **1**, not 2 as first classified | `BaseURLProvider` is in `openam-core`. A CHF-native overload is an in-tree change; reaching into commons `json-resource-http` to widen `HttpContext`'s package-private ctor would have been the wrong repair at the wrong tier |
| `Entity.setString` falls back to ISO-8859-1 when no `Content-Type` is set, silently mangling non-ASCII bodies for **every** CHF consumer | 2 (commons `http-framework`) | **Genuinely upstream** — the one of the three that is. RFC 7231 dropped the ISO-8859-1 default that this implements; the failure is silent and hits any embedder. Fix in commons, release, consume via the direct-override path. OpenAM's `getBytes(UTF_8)` + explicit header ([3c-1](migration/restlet/phase-3c-1-renderer.md)) stays correct either way and is not blocked on it |
| Restlet itself (2.4.4 + the jakarta fork) | 4 / 1 | **Deleted** — the whole migration. The fork being in-tree is what makes deletion an option |

## Related

- [docs/test-infrastructure.md](test-infrastructure.md) — which test layer will actually run and catch a
  given change; read it before writing the tests a framework fix needs.
- [docs/migration/restlet/chf-patterns.md](migration/restlet/chf-patterns.md) §2 — the concrete
  `Endpoints.from` semantics, kept current as the framework changes.
- [docs/migration/restlet/decisions.md](migration/restlet/decisions.md) — where a tier-1-vs-tier-2 call gets
  recorded for the Restlet migration.
