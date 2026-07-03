# Migration-docs review remediation — staged plan (2026-07)

Produced by the 2026-07-02 documentation review of `docs/migration/`. It fixes doc↔doc and doc↔code
drift accumulated during P1-5b–P1-5e, records missing scope decisions, and closes two substantive
parity/contract gaps discovered by cross-checking the docs against the AM server source.

> **Superseded scope note (2026-07-03).** After this remediation landed, the original **P1-5f** ("session
> dialog + error/expired/logout views + remember-me", the parity gate) was split 3-way — **P1-5f**
> (return/logout views + failure-nav), **P1-5j** (remember-me), **P1-5k** (session-timeout dialog + monitor
> + guard). The **parity gate and its `[P1-5h, P1-5i]` preconditions moved to P1-5k**. References below to
> "the P1-5f gate" and `plans/P1-5f-dialog-error-views-rememberme.md` reflect the pre-split state; the renamed
> successor is `plans/P1-5f-error-logout-views.md`, and the gate-flip step now lives in
> `plans/P1-5k-session-timeout-dialog.md`. See `plans/README.md`.

**How to use:** stages are ordered and independently landable — one stage = one commit = one session.
Stages 1–3 are documentation (+ one tiny TS mirror change); stages 4–5 are code and are tracked as new
tasks **P1-5h** and **P1-5i** (created in Stage 2). Do not start Stage 4/5 before Stage 2 has created
their task entries. Within a stage, items are independent — partial application is safe as long as the
stage's verification passes.

**Conventions for every stage:** preserve CDDL headers; plans/ADRs are append-only history — *annotate*
completed plans with dated correction blocks, don't rewrite them; tasks.yml status vocabulary is
`todo | in_progress | blocked | done` (never `migrated` — that belongs to route-ownership.yml).

## Findings → stage map

| # | Finding (short) | Severity | Stage |
|---|---|---|---|
| A1 | `zeroPageLoginAllowed` is a mock-invented field; real AM returns a `zeroPageLogin` object; referrer whitelist (security gate) dropped; tasks.yml falsely claims it | contract/security | 1 (doc), 2 (task), **4 (code)** |
| A2 | Redirect (SAML/social) return-leg resume unspecified in P1-5c plan and unimplemented; P1-5c marked done | parity | 2 (task), **5 (code)** |
| A3 | `gotoOnFail` + `detail.failureUrl` parsed but never acted on; no task owns them | parity | 2 |
| A4 | Social login + login-page self-service links have no owner; parity gate silently excludes them | scope | 2 |
| A5 | Deployment-time customization parity (themes/ThemeConfiguration, per-stage template overrides, confirm.html) has no decision anywhere | scope | 2 |
| A6 | P1-10 written scope understates the URL audit's must-preserve spellings | scope | 2 |
| B1 | `reference/eui-foundation.md` stale (pre-P1-5b) | drift | 1 |
| B2 | ADR-0004 basename clause contradicts ADR-0011; MIGRATION.md stale ADR-0008 pointer; `/EUI/login` spellings | drift | 1 |
| B3 | route-ownership.yml missing `confirmLogin` (already live in EUI), `logout`, `failedLogin`, `sessionExpired` | drift | 3 |
| B4 | tasks.yml: phase-1 status, P1-5e deps/detail, P1-5f step-10 vocabulary, P1-9 stale, hook naming | drift | 1 |
| B5 | "Vite 7" vs installed vite ^8; ADR-0007 "pin versions" vs `^` ranges | drift | 1 |
| B6 | MIGRATION.md Phase-0 omits P0-6; "react-bootstrap 5" phrasing ambiguity | cosmetic | 1 |

## Decisions locked for this plan (defaults — veto before executing the stage)

| Decision | Default | Alternative (why rejected) |
|---|---|---|
| A1 fix shape | Reshape `AmServerInfo` to the real `zeroPageLogin` object + implement whitelist (Stage 4) | Adapter keeping flat field — keeps the mock lying about the wire shape (ADR-0010 drift) |
| A2 tracking | New task P1-5i + dated gap note in P1-5c plan; P1-5f gate blocked on it | Reopen P1-5c — rewrites closed-task history |
| A3 home | Fold into P1-5f scope (failure-path UI is its theme, ~30 LOC) | Separate task — tracking overhead |
| A4 social login | New phase-2 task (needs `socialImplementations` serverinfo modeling); login-page self-service links added to P1-6 scope | Include in P1-5f gate — inflates the gate with serverinfo work |
| A5 customization | Short ADR-0012: parity *deferred* post-cutover, risk row added | Design mechanism now — no validated consumer demand yet |
| B3 granularity | Explicit rows for all 4 ancillary auth routes + TS mirror | Coarse "rides with login" note — map can't answer "who serves /logout" |
| B5 versions | Genericize prose to "Vite"; concrete number lives only in eui-foundation.md; reword ADR-0007 pin sentence to "locked via workspace lockfile" | Bump all to "Vite 8" — re-drifts on next major |
| Hook naming | Keep `useLogin.ts` (what exists); annotate the P1-5c plan mention | Rename to `useAuthenticationFlow.ts` — churn without benefit |
| authId storage (Stage 5) | Mirror the legacy `authId` cookie (name, path `/`) for cross-app coexistence interop — same precedent as P1-5f's `login` remember-me cookie | sessionStorage — simpler but breaks a flow that starts in one app and resumes in the other |

---

## Stage 1 — Factual doc corrections (docs only, no scope change)

> **Status: DONE (2026-07-03).** All 11 items applied. Scope clarifications agreed with the user before
> execution (verification's grep sweeps implied broader scope than the itemized edit list):
> - **ADR-0008 sweep** extended beyond the itemized MIGRATION.md edit to every other non-historical
>   pointer: `context.md`, `route-ownership.yml`, `decisions/0004-coexistence-separate-mounts.md`, and
>   three `tasks.yml` details (P0-6, P1-10, P4-2) now point at ADR-0011. `decisions/0011`'s own
>   `Supersedes: ADR-0008` / "the original ADR-0008 plan" mentions are untouched (legitimate history).
> - **`/EUI/login` (no `#/`) sweep** additionally fixed `tasks.yml`'s P1-5 detail. `decisions/0011`
>   line 9's `/EUI/login` example was deliberately left as-is — it illustrates the pre-hash-routing
>   (ADR-0008) world by design; rewriting it to `#/login` would misstate what that ADR-0011 paragraph
>   is arguing against.
> - `plans/README.md` gained a new "Other plans" section (none existed) linking this file.
>
> Verification: `grep -rn "ADR-0008"` / `"Vite 7"` / `/EUI/login` (no `#/`) sweeps all clean except this
> plan file itself and the two deliberate exceptions above; `tasks.yml` and `route-ownership.yml` parse
> as valid YAML (`npx js-yaml`).

Goal: every statement in the docs is true again. No planned-work changes, no code.

1. **`reference/eui-foundation.md` — refresh to post-P1-5e reality:**
   - `auth`: `AmCallback.type` is now `string` + `KnownCallbackType`/`KNOWN_CALLBACK_TYPES`; document
     `callbacks.ts` accessors (`getOutput`, `getPrompt`, `getChoices`, `getMessageType`, type guards,
     trackingCookie accessor), `CallbackForm` (props `{challenge, onSubmit, submitting}`; synthetic
     submit; TextOutput msg 0/1/2 as alerts; msg 4 no-op → P1-5g), `validateGoto`,
     `startAuthentication(transport, queryString?)`.
   - New `serverinfo` module (`fetchServerInfo`, `AmServerInfo`, `./serverinfo` package export).
     Note: shape being corrected by P1-5h/Stage 4 — write the section to match whichever has landed.
   - `eui`: `loginParams.ts` (`parseLoginParams`/`buildAuthQuery`/`extractIDTokens`/whitelist),
     `ConfirmLogin.tsx` + `/confirmLogin` route, `useLogin.ts` (multi-stage loop, polling schedule,
     408 handling with trackingCookie suppression, `isExistingSession`, zero-page auto-submit guard).
   - Deps: move `@tanstack/react-query` out of "Not yet present" (installed ^5.x, used by `useLogin`).
   - Rewrite "Not yet built" to the actual current gaps: P1-5f views/dialog/remember-me,
     ScriptTextOutput (P1-5g), redirect resume (P1-5i), serverinfo contract fix (P1-5h).
   - Update the "last updated for" line.
2. **ADR-0004** — append `Updated: 2026-07-02` note; in the build-requirement bullet replace
   "react-router `basename` from runtime config" with "router is `HashRouter`, no `basename`
   (ADR-0011); relocatability = relative Vite `base` + host-rewritten `<base href>`". Leave the rest.
3. **MIGRATION.md:** §4 tree — `compat/` annotation "(ADR-0008)" → "(ADR-0011, P1-10)". §5 Phase 1 and
   anywhere else: "redirects to `/EUI/login`" → "`/EUI/#/login`". §5 Phase 0: add the missing bullet
   for the P0-6 `/XUI` URL audit (→ `docs/migration/xui-url-audit.md`). "Vite 7" → "Vite" (B5 default).
4. **tasks.yml:**
   - `phase-1.status: todo` → `in_progress`.
   - P1-5e: `depends_on: [P1-5b]` → `[P1-5b, P1-5d]`; in `detail`, replace
     "(referrer whitelist + autoLoginAttempts guard)" with
     "(zeroPageLoginAllowed gate + autoLoginAttempts guard; referrer whitelist NOT implemented — see P1-5h)".
   - P1-9 → `done`, with a detail line: "patterns established in P0-5/P1-5 and documented in
     reference/eui-foundation.md (Vitest + Testing Library + shared MSW handlers, setup in src/test/setup.ts)".
   - P1-8 title: `/EUI/login` → `/EUI/#/login`. P0-1 detail: "Vite 7" → "Vite".
5. **plans/P1-5f-error-logout-views.md** (was `P1-5f-dialog-error-views-rememberme.md`) step 10: "P1-5 → migrated" → "P1-5 → done (and
   `route-ownership.yml` login → `status: migrated`)".
6. **plans/P1-5c-redirect-polling.md** — one-line annotations: files list
   "`useAuthenticationFlow.ts`" → "(landed as `useLogin.ts`)"; plus the Stage-2 gap note (may be
   combined into one edit if stages land together).
7. **plans/P1-5e-existing-session-zeropage.md** — add a dated correction block under "Key
   simplifications": real AM `/json/serverinfo/*` returns `zeroPageLogin: {enabled, refererWhitelist,
   allowedWithoutReferer}` (`openam-core-rest/.../models/ServerInfo.java:87`,
   `ServerInfoResource.java:185`) — the flat `zeroPageLoginAllowed` was the mock's own invention, so
   "the current AmServerInfo exposes…" was circular; whitelist is required for parity+security; fixed by P1-5h.
8. **plans/README.md:** fix the "Dependency shape" sentence (P1-5e also builds on P1-5d); add an
   "Other plans" table row linking this file.
9. **context.md:** "Vite 7" → "Vite"; Status line "Next: Phase 1 (login slice)" → "Phase 1 in
   progress — login parity P1-5b–g (see tasks.yml)".
10. **ADR-0007:** "Vite 7" → "Vite (major version at scaffold time; `package.json` is authoritative)";
    replace "Pin versions at scaffold time…" with "Versions are locked via the workspace lockfile;
    upgrade deliberately". Append `Updated: 2026-07-02` note.
11. **glossary.md:** add a `react-bootstrap` entry clarifying that "react-bootstrap 5" in these docs
    means "react-bootstrap (v2.x) targeting Bootstrap 5".

**Verification:** `grep -rn "ADR-0008" docs/migration MIGRATION.md` shows only the ADR file itself,
its README index row, and ADR-0011's supersedes references; `grep -rn "Vite 7"` returns nothing;
`grep -rn "/EUI/login"` (without `#/`) returns nothing; re-read eui-foundation.md against
`commons-ui-next/src` and `openam-ui-eui/src/features/auth` — every claim checkable in ≤1 file open.

---

## Stage 2 — Scope & decision records (docs only, changes planned work)

> **Status: DONE (2026-07-03).** All 7 items applied:
> - New tasks **P1-5h** and **P1-5i** added to `tasks.yml` (phase-1), each `plan:` pointing at this file.
> - **P1-5f** gate hardened: `depends_on` → `[P1-5b, P1-5h, P1-5i]` in `tasks.yml`; mirrored as a dated
>   "Gate hardening" note under Goal in `plans/P1-5f-…md`, plus a reminder on its (renumbered) gate-flip step.
> - **A3** folded into P1-5f: new implementation step 4 ("Failure navigation"), extended step 10 (Tests),
>   `tasks.yml` P1-5f detail, and a new row in `plans/README.md`'s sub-feature table. Inserting the step
>   renumbered P1-5f's original steps 4–10 to 5–11 — content unchanged, only step numbers shifted.
> - **A4** given owners: `tasks.yml` P1-6 detail extended for self-service links; new task **P2-6** for
>   social login; both noted as documented exclusions in P1-5f's Out-of-scope section.
> - **A5** — new **ADR-0012** (deployment-time customization parity deferred post-cutover), indexed in
>   `decisions/README.md`; risk row added to `MIGRATION.md` §7 and a caveat line to §8.
> - **A6** — P1-10's `tasks.yml` detail expanded to enumerate the must-preserve spellings from
>   `xui-url-audit.md` (composite `&` params, realm path-suffix, outside-hash query, aux routes, phase-2/3
>   appends, `confirm.html` exclusion).
> - **A2**'s dated gap note added to `plans/P1-5c-redirect-polling.md` (Stage 2 item 2), pointing at P1-5i.
>
> Verification: `tasks.yml` parses (`npx js-yaml`); every A-finding (A1–A6, plus A2 already tracked) now
> maps to a task id or ADR-0012; `decisions/README.md` lists ADR-0012.

Goal: every known parity gap has a written owner or a written "not doing it" decision.

1. **New task `P1-5h` in tasks.yml** — "Login parity — serverinfo `zeroPageLogin` contract fix +
   referrer whitelist" (`status: todo`, `depends_on: [P1-5e]`, `plan:` → this file, Stage 4).
   Detail: mock/type model a `zeroPageLoginAllowed` flat boolean that does not exist in real AM;
   reshape to the real `zeroPageLogin` object and implement the referrer-whitelist gate (security
   regression otherwise). ADR-0010 drift instance.
2. **New task `P1-5i` in tasks.yml** — "Login parity — RedirectCallback return-leg resume (authId
   tracking cookie)" (`status: todo`, `depends_on: [P1-5c]`, `plan:` → this file, Stage 5).
   Detail: P1-5c stored nothing across the IdP round-trip; a federation login restarts at stage 1 on
   return. Add the dated gap note to `plans/P1-5c-redirect-polling.md` ("Gap found 2026-07-02: …
   resume leg not specified/implemented — see P1-5i").
3. **Gate hardening:** P1-5f `depends_on: [P1-5b]` → `[P1-5b, P1-5h, P1-5i]`, and note in its detail
   that the parity gate must not flip `login → migrated` before both land. Mirror the note in
   `plans/P1-5f-…md`.
4. **A3 — fold `gotoOnFail` + `detail.failureUrl` into P1-5f:** add an implementation step to
   `plans/P1-5f-…md` ("Failure navigation: on terminal auth failure, if `gotoOnFail` param present →
   validate via `validateGoto` then navigate; a 401 body carrying `detail.failureUrl` → hard
   `window.location.href` navigation — legacy `goToFailureUrl`, see `AuthNService.js`"), extend its
   test table, and mention both in tasks.yml P1-5f detail. Add a row to plans/README's sub-feature
   table (`gotoOnFail`/`failureUrl` → P1-5f).
5. **A4 — login-page chrome ownership:**
   - tasks.yml P1-6: extend detail to include rendering the login page's self-service links
     (`showForgotPassword`/`showForgotUserName`/`showSelfRegistration` from serverinfo flags), not
     just the anonymousProcess flows.
   - New phase-2 task `P2-6` — "Social login buttons on login page (`socialImplementations` from
     serverinfo)" (`status: todo`). Note in `plans/P1-5f-…md`'s Out-of-scope that the gate explicitly
     excludes social login (→ P2-6) and self-service links (→ P1-6) — documented exclusions, not gaps.
6. **A5 — ADR-0012 "Deployment-time customization parity deferred":** Context — legacy supports
   rebrand-without-rebuild (`config/ThemeConfiguration.js`/`AppConfiguration.js` excluded from r.js
   optimization, `/XUI/themes/`, per-auth-module template overrides `templates/openam/authn/${stage}.html`,
   `confirm.html` static page); Vite bundles everything, so no equivalent exists. Decision — parity is
   **out of scope until after cutover**; revisit then with a runtime-config/CSS-custom-properties
   approach. Consequences — customized deployments cannot cut over blindly; add a risk row to
   MIGRATION.md §7 and a caveat line to §8 (definition of done); the audit's "best-effort" custom-UI
   rows point here. Alternatives — design now (rejected: no validated demand yet). Add to
   decisions/README.md index.
7. **A6 — expand P1-10's tasks.yml detail** to enumerate the audit's must-preserve spellings
   (input: `xui-url-audit.md`):
   - `#login` → `#/login`; `#!/X` → `#/X`.
   - Composite `&` fragment params: `#login&realm=/x&goto=…` → `#/login?realm=/x&goto=…`
     (react-router `useSearchParams` only sees `?`-delimited params — legacy parsed `&`-composites).
   - Realm path-suffix: `#login/myRealm` → `#/login?realm=/myRealm`.
   - Outside-hash query: `/XUI/?realm=x#login` — merge `window.location.search` into the fragment
     query (`#/login?realm=x`); HashRouter never sees `location.search`.
   - Anonymous-process/aux routes: `#passwordReset/…`, `#register/…`, `#continuePasswordReset…`
     (regex), `#logout/`, `#failedLogin…`, `#confirmLogin/` — grown per slice.
   - Phase-2/3 appends: `#uma/share/{id}`, `#uma/requests/{id}`, `#realms/%2F/dashboard`.
   - `confirm.html` is a static page → cutover/P4 concern, not hash normalization.
   - Constraint (from P1-5d): normalization must preserve every query param.

**Verification:** tasks.yml parses (`npx js-yaml` or the route-ownership drift test's yaml load);
every A-finding now maps to a task id or an ADR; decisions/README lists ADR-0012.

---

## Stage 3 — Route-ownership completion (yml + TS mirror + drift test)

> **Status: DONE (2026-07-03).** All 4 items applied:
> - `route-ownership.yml` gained `confirmLogin` (`eui`/`in_progress`), `logout`/`failedLogin`/`sessionExpired`
>   (`xui`/`planned`), inserted right after `login` in the phase-1 block, plus a header comment noting these
>   ancillary routes are now tracked explicitly.
> - `routeOwnership.ts` gained the matching four `{path, owner}` pairs at the same ordinal position.
> - `plans/P1-5f-…md` step 9 (the gate-flip step — renumbered by Stage 2) extended: on landing, also flip
>   `logout`/`failedLogin`/`sessionExpired` → `owner: eui, status: migrated` and `confirmLogin` →
>   `status: migrated`, with the matching `routeOwnership.ts` edits in the same commit.
>
> Verification: `route-ownership.yml` parses (`npx js-yaml`); `routeOwnership.test.ts` (all 3 assertions,
> including the ordered path+owner sync) passes; full `npm run test:run` in `openam-ui-eui` — 87/87 passed.
> `npm run lint` / `npm run typecheck` both fail, but **only** on a pre-existing unrelated error (unused
> `AUTH_CHALLENGE` import in `LoginPage.test.tsx`, introduced by the zero-page-login work, commit
> `992bd52e92`) — not touched by or related to this stage's route-ownership changes. Left as-is (out of
> scope for this stage); flagged here for a future cleanup pass.

Goal: the map answers "who serves this URL" for every auth route that exists today.

1. **`route-ownership.yml`** — append to the phase-1 section, after `login`:
   ```yaml
   - path: confirmLogin        # realm-change interstitial; rides the login gate
     owner: eui
     status: in_progress
     slice: phase-1
   - path: logout              # must-preserve external URL (#logout/, see xui-url-audit.md)
     owner: xui
     status: planned
     slice: phase-1
   - path: failedLogin
     owner: xui
     status: planned
     slice: phase-1
   - path: sessionExpired
     owner: xui
     status: planned
     slice: phase-1
   ```
2. **`openam-ui-eui/src/config/routeOwnership.ts`** — insert the same four `{path, owner}` pairs at
   the same ordinal positions (the drift test compares **ordered** pairs).
3. **`plans/P1-5f-…md` step 8** — extend the gate flip: on landing, also flip `logout`, `failedLogin`,
   `sessionExpired` → `owner: eui, status: migrated`, and `confirmLogin` → `status: migrated`
   (+ the TS mirror in the same commit).
4. Optional: one header line in route-ownership.yml noting that ancillary auth routes are tracked
   explicitly as of this change.

**Verification:** `npm run test:run` in `openam-ui/openam-ui-eui` — `routeOwnership.test.ts` green;
`npm run lint` + `npm run typecheck` green.

---

## Stage 4 — Code: serverinfo contract fix + referrer whitelist (task P1-5h)

> **Status: DONE (2026-07-03).** All changes applied:
> - `commons-ui-next/src/serverinfo/types.ts`: added `AmZeroPageLogin = { enabled, refererWhitelist,
>   allowedWithoutReferer }`; replaced `AmServerInfo.zeroPageLoginAllowed: boolean` with
>   `zeroPageLogin: AmZeroPageLogin`. Field-name audit sub-step: confirmed via grep across the Java
>   backend (`ServerInfo.java`, `ServerInfoResource.java`) and the legacy XUI source that `FQDN` and
>   `inplaceUpgrade` have **zero grounding anywhere** (not a rename target — wholly invented, unlike
>   `zeroPageLoginAllowed` which at least mapped to a real-but-reshaped field) — dropped both. No other
>   field-*name* mismatches found (`socialImplementations: string[]` vs. the real
>   `List<SocialAuthenticationImplementation>`, and the missing `forgotUsername`/`kbaEnabled`/
>   `cookieHttpOnly`/`cookieSameSite` fields, are shape/completeness gaps, not invented names — left
>   alone as out of scope for this stage; flagged here for a future hygiene pass).
> - `commons-ui-next/src/serverinfo/zeroPageLogin.ts` (new): `isZeroPageLoginAllowed`, an exact port of
>   legacy `RESTLoginView.isZeroPageLoginAllowed`; exported from the barrel along with `AmZeroPageLogin`.
> - `commons-ui-next/src/mock/fixtures/serverinfo.ts`: `SERVER_INFO.zeroPageLogin` defaults to
>   `{ enabled: false, refererWhitelist: [], allowedWithoutReferer: false }`; added
>   `SERVER_INFO_ZERO_PAGE_ENABLED` (`enabled: true, allowedWithoutReferer: true`) for the common
>   "zero-page allowed" test scenario. Both re-exported from `mock/index.ts`; `mock/types.ts` re-exports
>   `AmZeroPageLogin` alongside `AmServerInfo`.
> - `openam-ui-eui/src/features/auth/LoginPage.tsx`: both zero-page gate checks (auto-submit effect and
>   the spinner render-guard) now go through a memoized `isZeroPageLoginAllowed(serverInfo.zeroPageLogin,
>   document.referrer)` instead of the flat boolean.
> - Tests: new `serverinfo/zeroPageLogin.test.ts` (disabled; no-referrer × `allowedWithoutReferer`;
>   empty-whitelist; whitelist hit/miss — 4 cases). `LoginPage.test.tsx`'s zero-page describe block
>   updated to the new fixture shape (`SERVER_INFO_ZERO_PAGE_ENABLED`) and gained a whitelist-miss case
>   (referrer stubbed via `Object.defineProperty(document, 'referrer', ...)`, not on the whitelist ⇒
>   form renders, no auto-submit). `test/handlers.test.ts`'s serverinfo-handler test swapped its
>   `FQDN` round-trip assertion for `realm` (field removed).
> - Docs: `tasks.yml` P1-5h → `done` (detail rewritten past-tense, notes the dropped invented fields);
>   P1-5e's detail line updated (whitelist gate no longer "NOT implemented"); a dated **Resolved**
>   annotation added under P1-5e plan's existing 2026-07-02 correction blockquote (append-only — the
>   original correction text is untouched); `eui-foundation.md`'s serverinfo section rewritten to the
>   real shape + the new `isZeroPageLoginAllowed` export, the `LoginPage.tsx` description line updated,
>   and the now-resolved "`serverinfo` contract fix — P1-5h" row removed from "Not yet built".
>
> Verification: `npm run typecheck && npm run lint && npm run test:run` green in both packages —
> `commons-ui-next` 31/31 tests, `openam-ui-eui` 88/88 tests (was 87; +1 for the whitelist-miss case).
> Manual `dev:mock` walk (IDToken URL, `zeroPageLogin.enabled: true` vs `false`) not run in this
> environment (no dev server available); covered instead by the equivalent MSW-driven test scenarios.
> Note: Stage 3's flagged pre-existing `AUTH_CHALLENGE` unused-import lint/typecheck failure is gone —
> resolved by an intervening commit (`3963689d99`) unrelated to this stage.

Goal: the serverinfo model matches real AM, and zero-page login enforces the legacy referrer gate.

**Ground truth:** `ServerInfoResource.java:185` puts `zeroPageLogin` = `ZeroPageLoginConfig`
(`ServerInfo.java:87`) into the response: `{ enabled: boolean, refererWhitelist: string[],
allowedWithoutReferer: boolean }`. Legacy consumption: `RESTLoginView.js:191–204`:

```js
isZeroPageLoginAllowed () {
    var referer = document.referrer,
        whitelist = Configuration.globalData.zeroPageLogin.refererWhitelist;
    if (!Configuration.globalData.zeroPageLogin.enabled) { return false; }
    if (!referer) { return Configuration.globalData.zeroPageLogin.allowedWithoutReferer; }
    return !whitelist || !whitelist.length || whitelist.indexOf(referer) > -1;   // exact-string match
}
```

**Changes:**

| File | Action |
|---|---|
| `commons-ui-next/src/serverinfo/types.ts` | Add `AmZeroPageLogin = { enabled: boolean; refererWhitelist: string[]; allowedWithoutReferer: boolean }`; replace `zeroPageLoginAllowed: boolean` with `zeroPageLogin: AmZeroPageLogin`. **Sub-step:** audit every other `AmServerInfo` field name against `ServerInfo.java` — fix any other invented names while here (ADR-0010 hygiene). |
| `commons-ui-next/src/serverinfo/zeroPageLogin.ts` (new) | Pure `isZeroPageLoginAllowed(config: AmZeroPageLogin, referrer: string): boolean` — exact port of the legacy logic above (empty/missing whitelist ⇒ allowed when enabled + referrer present). Export from the barrel. Pure + generic ⇒ belongs in commons-ui-next (ADR-0002 clean). |
| `commons-ui-next/src/mock/fixtures/serverinfo.ts` | Replace the flat field with the object (default `{ enabled: false, refererWhitelist: [], allowedWithoutReferer: false }`); add an enabled variant for tests. |
| `openam-ui-eui/src/features/auth/LoginPage.tsx` | Gate becomes `isZeroPageLoginAllowed(serverInfo.zeroPageLogin, document.referrer)` (both zero-page branches, ~lines 146 and 174). |
| Tests | New `zeroPageLogin.test.ts`: disabled ⇒ false; no referrer × `allowedWithoutReferer` both ways; whitelist hit / miss / empty. Update `LoginPage.test.tsx` zero-page scenarios to the new fixture shape; add a whitelist-miss case (referrer set, not whitelisted ⇒ form renders, no auto-submit). |
| Docs | tasks.yml P1-5h → done; strike the Stage-1 correction pointer in the P1-5e plan (mark resolved); update eui-foundation serverinfo section. |

**Verification:** `npm run test:run` + `typecheck` + `lint` in both packages; `dev:mock` manual:
IDToken URL with mock `zeroPageLogin.enabled: true` auto-submits; with `enabled: false` renders the form.

---

## Stage 5 — Code: RedirectCallback return-leg resume (task P1-5i)

> **Status: DONE (2026-07-03).** All changes applied:
> - `commons-ui-next/src/auth/trackingToken.ts` (new): `getTrackingToken`/`setTrackingToken`/`clearTrackingToken`
>   — a port of `AuthenticationToken.jsm`'s `authId` cookie (name kept for XUI/EUI coexistence interop;
>   path `/`; optional `{ domains?, secure? }`, one cookie written per domain or a host-only cookie when
>   omitted). The cookie-string builder (`buildTrackingCookieStrings`) is factored out as a pure function
>   so it's unit-testable in this package's `node`-environment Vitest run (no DOM) — mirrors the legacy
>   `CookieHelper.createCookie` (pure) vs. `setCookie` (impure) split. `get`/`set`/`clear` themselves touch
>   `document.cookie` and are exercised indirectly via the jsdom-based `openam-ui-eui` tests instead.
> - `commons-ui-next/src/auth/authenticate.ts`: added `resumeAuthentication(transport, authId, queryString?)`
>   — POSTs `{ authId }` instead of an empty `begin()`, matching `AuthNService.getRequirements`'s
>   tracked-token branch. Simplification from legacy (documented, not silent): legacy's body also merges in
>   `Configuration.globalData.auth.urlParams`, duplicating what `submitRequirements`'s URL-querystring
>   append already carries; the port relies on the querystring alone (same pattern `startAuthentication`
>   already uses), since the body-level duplication doesn't add information AM doesn't already have.
> - `openam-ui-eui/src/features/auth/useLogin.ts`: on `startAuth` (mount and every `restart()`), checks
>   `getTrackingToken()` first — if set, calls `resumeAuthentication` instead of `startAuthentication` and
>   clears the cookie only once the response resolves to a non-`'failure'` kind (mirrors legacy's
>   jQuery-`.done()`-only-fires-on-2xx semantics: a next stage or success clears it, a 401/408 leaves it).
>   When a `requirements` step carries a `RedirectCallback` with a tracking-cookie output and no token is
>   already stored, it calls `setTrackingToken(challenge.authId)` — this runs before `LoginPage`'s own
>   effect performs the actual navigation (hook effects run in call order on the same render pass), so the
>   cookie is set before the page navigates away. The former in-memory `hasTrackingCookieRef` (used only to
>   suppress 408 auto-restart) was **replaced** with a direct `getTrackingToken()` check at 408-time — this
>   is both more faithful to legacy (a single cookie check, not a parallel in-memory flag) and closes an
>   infinite-loop risk the old ref would have had once resume was added (a 408 during a resume attempt
>   left the cookie in place per the point above; re-checking the real cookie means the retry is correctly
>   suppressed instead of looping). The hook now also exposes `isTimedOut` for the suppressed-408 case.
> - `openam-ui-eui/src/features/auth/LoginPage.tsx`: destructures `isTimedOut`; a tracked 408 now shows
>   `t('config.messages.CommonMessages.loginTimeout')` (translation key already existed, unused until now)
>   and renders it in a new terminal branch instead of falling through to `return null` — mirrors
>   `AuthNService.js:176–180`'s "show the timeout message, don't restart" behavior for a tracked authId.
>   A non-tracked 408 is unchanged (silent auto-restart inside the hook, no message).
> - Mock fixtures/handlers: **no changes needed** — `resolveAuthenticateBody`'s existing
>   `authId === REDIRECT_GET_AUTH_ID || authId === REDIRECT_POST_AUTH_ID → AUTH_SUCCESS` branch already
>   answers a bare `{ authId }` resume POST correctly, since it doesn't inspect `callbacks`. Documented
>   here as a deliberate no-op rather than silently skipping the Changes table's fixture row.
> - Tests: `trackingToken.test.ts` (pure builder, 4 cases: host-only, per-domain, secure, expires).
>   `auth.test.ts` gained 2 `resumeAuthentication` cases (tracked authId → success; unknown authId →
>   failure). `LoginPage.test.tsx` gained a new "return-leg resume (P1-5i)" describe block (3 cases: cookie
>   set before the hidden-form POST redirect submits; mount-with-cookie resumes with no `begin()` call and
>   clears the cookie on success; a tracked 408 shows the timeout message, does not restart, and leaves the
>   cookie in place).
> - Docs: `tasks.yml` P1-5i → `done` (detail rewritten past-tense); a dated **Resolved** annotation added
>   under `P1-5c-redirect-polling.md`'s existing 2026-07-02 gap-note blockquote (append-only — the original
>   gap note is untouched); `eui-foundation.md`'s auth section gained `resumeAuthentication` and
>   `trackingToken.ts` entries, the `LoginPage.tsx`/`useLogin.ts` description lines were updated, the
>   now-resolved P1-5i row was removed from "Not yet built", and the "last updated for" line now points at
>   this stage.
>
> Verification: `npm run typecheck && npm run lint && npm run test:run` green in both packages —
> `commons-ui-next` 37/37 tests (was 31; +6), `openam-ui-eui` 91/91 tests (was 88; +3). Manual `dev:mock`
> walk of the redirect scenario (redirect out → simulated return → resumed stage → success) not run in
> this environment (no dev server available); covered instead by the equivalent MSW-driven test scenarios
> above. P1-5f's gate `depends_on` already includes P1-5h and P1-5i (set in Stage 2) — both now done, but
> flipping `route-ownership.yml` login → `migrated` remains P1-5f's own task, not touched here.

Goal: a federation (SAML/OAuth) login resumes after the IdP round-trip instead of restarting.

**Legacy protocol (ground truth, `AuthNService.js` + `AuthenticationToken.jsm`):**
- **Store** (AuthNService:123–124): when a challenge carries `authId` and one of its callbacks has
  tracking (RedirectCallback with `trackingCookie: true` output), and no token is already stored →
  set cookie **`authId`** = `challenge.authId` (path `/`, domain from serverinfo `cookieDomains`,
  secure from serverinfo `secureCookie`).
- **Resume** (AuthNService:245–251): on login-flow start, if the `authId` cookie exists → **skip
  `begin()`**; POST `{ authId: <cookie>, ...url params }` to `/json/authenticate`; on completion
  remove the cookie. AM replies with the next stage or success.
- **408 interplay** (AuthNService:176–180): while a tracked `authId` exists, a 408 shows the
  `loginTimeout` message and does **not** restart — `useLogin.ts:90–98` already suppresses restart;
  verify the message behavior matches.

**Changes:**

| File | Action |
|---|---|
| `commons-ui-next/src/auth/trackingToken.ts` (new) | `get/set/clear` for the `authId` cookie — mirror the legacy cookie name for cross-app coexistence interop (same precedent as P1-5f's `login` remember-me cookie). Accept optional `{ domain, secure }` from serverinfo. |
| `commons-ui-next/src/auth/authenticate.ts` | Add `resumeAuthentication(transport, authId, queryString?): Promise<AuthStep>` — POSTs `{ authId }` (+ params) instead of an empty begin. |
| `commons-ui-next/src/auth/index.ts` | Export both. |
| `openam-ui-eui/src/features/auth/useLogin.ts` | On start: if `trackingToken.get()` → `resumeAuthentication` and clear the token after the response (success *or* next stage — legacy clears on `done`). On seeing a redirect stage with `trackingCookie` → `trackingToken.set(authId)` before navigating away (extend the existing detection at ~line 90). |
| `commons-ui-next/src/mock/{fixtures,handlers}/authenticate.ts` | Extend the P1-5c redirect scenario with the return leg: POST carrying the tracked `authId` → next stage / success fixture. |
| Tests | Cookie set before redirect navigation; mount-with-cookie resumes (no `begin`) and clears the cookie; 408-with-cookie shows timeout message without restart. |
| Docs | tasks.yml P1-5i → done; mark the P1-5c plan gap note resolved; eui-foundation auth section. |

**Verification:** `npm run test:run` + `typecheck` + `lint` in both packages; `dev:mock` walk of the
mock redirect scenario end-to-end (redirect out → simulated return → resumed stage → success).

---

## Exit checklist (after all stages)

- [ ] `grep` sweeps from Stage 1 verification all clean.
- [ ] Every A-finding: task done or ADR recorded; every B-finding: corrected.
- [ ] Drift test, lint, typecheck, `test:run` green in `openam-ui-eui` and `commons-ui-next`.
- [ ] P1-5f gate `depends_on` includes P1-5h + P1-5i (gate cannot flip login → migrated early).
- [ ] eui-foundation.md spot-check: every claim verifiable against the source tree.
