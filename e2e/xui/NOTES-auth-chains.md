# Authentication chain administration — what a Playwright spec can rely on

Findings verified empirically against `http://openam.example.org:8080/openam` (OpenAM
16.2.0-SNAPSHOT) on 2026-08-11, with throwaway Chromium/node runs as `amadmin`. Everything ran
inside one scratch realm created and deleted over REST. Nothing under the root realm's
authentication configuration was created, edited or deleted, and **no realm's `adminAuthModule` or
`orgConfig` was written or repointed**. See [Restore](#12-restore).

Companion to `NOTES-auth-modules.md` (task 1.14), whose fixtures and traps this inherits. Read §7
there — the stale-view trap — before anything else here: it is the single thing most likely to make
a chain spec produce nonsense, and §5 below is a worked example of it faking a flaky drag.

## 1. Routes

`config/routes/admin/RealmsRoutes.js:66-91`. Same `realmHash()` from `common/realms-commons.mjs`.

| screen | hash | helper |
| --- | --- | --- |
| list | `#realms/%2Fscratch/authentication-chains` | `realmHash(realmPath, "authentication-chains")` |
| create | `#realms/%2Fscratch/authentication-chains/new` | `realmHash(realmPath, "authentication-chains/new")` |
| editor | `#realms/%2Fscratch/authentication-chains/edit/<name>` | `realmHash(realmPath, \`authentication-chains/edit/${name}\`)` |

Unlike a module's route there is **no type segment** — a chain is identified by name alone.
Navigating to a name that does not exist leaves the hash unchanged and posts `Not Found` to
`#messages`.

## 2. Chain list (`ChainsView.js`, `ChainsTemplate.html`)

| what | selector | notes |
| --- | --- | --- |
| title | `#content h1` | `Chains` |
| row | `tr.sorted-chains` | **the row itself carries no data attribute** — unlike the modules list |
| row (by name) | `tr.sorted-chains`, `{ hasText: name }` | or scope from the checkbox/button below |
| name link | `tr.sorted-chains td:nth-child(2) a.edit-chain-btn` | |
| pencil link | `tr.sorted-chains td.fr-col-btn-2 a.edit-chain-btn` | **two** `a.edit-chain-btn` per row; both href the same edit route |
| checkbox | `input[type=checkbox][data-chain-name="<name>"]` | |
| row delete | `button[data-delete-chain][data-chain-name="<name>"]` | |
| bulk delete | `[data-delete-chains]` | in `.btn-toolbar.page-toolbar`, `disabled` until something is checked |
| select all | `[data-select-all]` | |
| add chain | `[data-add-chain]` | an `<a>`, text "Add Chain" |

A fresh sub-realm lists exactly `["ldapService", "amsterService"]`.

Checking a row adds `selected` to the `<tr>` and enables `[data-delete-chains]`; the list re-renders
after a delete and the bulk button goes back to `disabled`.

## 3. Create form (`AddChainView.js`, `AddChainTemplate.html`)

| what | selector | notes |
| --- | --- | --- |
| title | `#content h1` | **`Add Chain`** — the i18n key is `chains.newChain` but the string is "Add Chain", not "New Chain" |
| name | `#name` (also `[data-chain-name]`) | `required`, `autofocus` |
| create | `[data-save]` | label "Create" |
| cancel | `.panel-footer a.btn-default` | |

There is no type to choose — a chain has only a name. `validateChainProps` is bound to
`keyup`/`change` on `[data-chain-name]`.

| state | `[data-save]` disabled | message |
| --- | --- | --- |
| fresh / empty name | yes | — |
| `page.fill()` alone | **yes** | `fill` does not fire `keyup`; follow it with `.press("End")` or use `pressSequentially` |
| valid new name | no | — |
| duplicate name | yes | `A Chain with the same name already exists` (danger) |
| **name containing a space** | **no — accepted** | unlike modules, spaces are *not* rejected here |

Scope the row selector with `tr` on the list: `[data-chain-name]` also matches this form's input.

On success it routes to `.../authentication-chains/edit/<name>` — that route change is the only
success oracle, the create is silent.

## 4. The chain editor (`EditChainView.js`, `EditChainTemplate.html`)

| what | selector | notes |
| --- | --- | --- |
| title | `#content h1` | the chain name (dynamic title) |
| subtitle | `#content h4.page-type` | "CHAINS" |
| tabs | `.tab-menu .nav-tabs li a` | `["Edit Chain", "Settings"]` — real tabs here, unlike the module form |
| link list | `ol#sortableAuthChain` | `hidden` class while the chain is empty |
| a link | `#sortableAuthChain li.chain-link` | |
| add module | `[data-add-new-module]` | **two on the page** — one in `.btn-toolbar`, one in `.call-to-action-block`; only one is visible at a time |
| save links | `[data-save-chain]` | "Save Changes", `disabled` while the chain is empty |
| **delete chain** | `.page-header [data-delete]` | **must be scoped** — every link also has a `[data-delete]` |
| warning alert | `#chains #alertContainer .alert` | **must be scoped** — `#alertContainer` is a duplicated id, see below |
| settings save | `[data-save-settings]` | on the Settings tab; saves the redirect URLs, not the links |

### Two id collisions worth knowing

- `#alertContainer` exists **twice** (`count() === 2`): the chain-validation one inside `#chains`,
  and a `<td id="alertContainer">` inside `#postProcessView` on the Settings tab. A bare
  `#alertContainer` locator is a strict-mode violation. Use `#chains #alertContainer`.
- `[data-delete]` is both the header's delete-chain button and every link's remove button. Use
  `.page-header [data-delete]` for the chain and `li.chain-link [data-delete]` for a link.

### An empty chain

| observed | value |
| --- | --- |
| `.call-to-action-block` visible | true, `<h3>` "CHAINS REQUIRE AT LEAST ONE MODULE" |
| `#sortableAuthChain` has `hidden` | true |
| `#chains .btn-toolbar` has `hidden` | true |
| `[data-save-chain]` disabled | true |
| REST | `{"authChainConfiguration":[],"loginSuccessUrl":[""],"loginFailureUrl":[""],"loginPostProcessClass":[],"_id":"e2eChain"}` |

Adding the first link flips all four (`validateChain`, `EditChainView.js:269`).

## 5. Adding a module link (`EditLinkView.js`, `EditLinkTemplate.html`)

`[data-add-new-module]` opens a BootstrapDialog. **Both selects are selectize-decorated
`SelectComponent`s** — but they are *not* addressed the same way, which is the trap:

| | module select | criteria select |
| --- | --- | --- |
| container | `[data-module-select]` | `[data-criteria-select]` |
| control | `.selectize-input` | `.selectize-input` |
| **options** | `.selectize-dropdown-content > div` | `.selectize-dropdown-content .option` |
| `data-value` | array index `0..n` | array index `0..3` |
| option text | `"e2eModA SecurID"` (`_id` + typeDescription) | `Required` / `Optional` / `Requisite` / `Sufficient` |

The module select is given an `optionComponent`/`itemComponent`
(`templates/admin/views/realms/authentication/SelectModuleOption.html`), and
`SelectComponent.getRenderer` returns `component.render().$el.html()` — the component's *inner*
HTML. That replaces selectize's own option element wholesale, so **`.option` and `.item` classes are
never applied** to the module dropdown. `[data-module-select] ... .option` matches zero elements.
The criteria select has no custom renderer, so it keeps `.option`.

Never select by `data-value`: it is the option's index in the array, not the module name.

```js
// add a link
await page.locator(".btn-toolbar [data-add-new-module]").click();
await page.locator(".bootstrap-dialog").waitFor();
await page.locator(".bootstrap-dialog [data-module-select] .selectize-input").click();
await page.locator(".bootstrap-dialog [data-module-select] .selectize-dropdown-content > div",
    { hasText: /e2eModA/ }).first().click();
await page.locator(".bootstrap-dialog [data-criteria-select] .selectize-input").click();
await page.locator(".bootstrap-dialog [data-criteria-select] .selectize-dropdown-content .option",
    { hasText: /^Required$/ }).first().click();
await page.locator(".bootstrap-dialog #saveBtn").click();
await page.locator(".bootstrap-dialog").waitFor({ state: "detached" });
```

| dialog part | selector | notes |
| --- | --- | --- |
| title | `.bootstrap-dialog .bootstrap-dialog-title` | `New Module` / `Edit Module` |
| OK | `.bootstrap-dialog #saveBtn` | the only button with a stable id; Cancel's id is a fresh uuid |
| Cancel | `.bootstrap-dialog .modal-footer button.btn-default` | |
| option key/value | `.bootstrap-dialog #optionsKey`, `#optionsValue` | |
| add option | `.bootstrap-dialog [data-add-option]` | |
| delete option | `.bootstrap-dialog [data-delete-option]` | |

`validateDialog` enables OK only once both module and criteria are set. **It is only ever called
from a select's `onChange`**, so on the *edit* dialog — where both are already populated — OK is
still rendered `disabled` and stays that way until something is actually changed. A spec that opens
a link to read it and then clicks OK will find OK unclickable.

The dialog is `closable: false`: there is no ✕ and no backdrop dismiss.

A duplicate module in one chain is accepted (two links on `e2eModC` saved fine).

### What a rendered link looks like (`LinkView.js`, `LinkTemplate.html`)

| what | selector | notes |
| --- | --- | --- |
| module name | `li.chain-link h3.media-heading` | this is the ordering oracle |
| type | `li.chain-link .status` | e.g. `SecurID` |
| options count | `li.chain-link .badge` | |
| **criteria** | `li.chain-link [data-select-criteria]` | a **plain `<select>`** — no selectize anywhere on the link |
| criteria info | `li.chain-link [data-auth-criteria-info]` | popover, `trigger: manual`, opened on mouseenter/focusin |
| drag handle | `li.chain-link .panel-menu .btn-group button` (first, `.fa-arrows`) | decorative — the whole `li` is draggable |
| edit link | `li.chain-link [data-edit]` | reopens the dialog |
| remove link | `li.chain-link [data-delete]` | **no confirmation** — removes the `li` immediately |
| criteria footer | `li.chain-link .panel-footer.criteria-view` | re-rendered on every criteria change |

## 6. THE REORDER

`EditChainView` declares `"sortable"` (`main.js:75` → `libs/jquery-sortable-0.9.13`, shimmed
`deps: ["jquery"]` at `main.js:163`) and initialises it in `initSortable` (`EditChainView.js:66`)
on `ol#sortableAuthChain`, once, after the links render. Its options, confirmed at runtime from
`$("ol#sortableAuthChain").data("sortable").group.options`:

| option | value | consequence |
| --- | --- | --- |
| **`delay`** | **100** | **the drag does not arm until 100 ms after `mousedown`; every `mousemove` before that is discarded** |
| `distance` | 0 (default) | any movement counts once the delay is met |
| `vertical` | true | |
| `exclude` | `li:not(.chain-link)` | |
| `itemSelector` | `li` (default) | |
| `handle` | `""` (default) | the whole `li` is a handle |
| `onMousedown` | default | **refuses to start on `input` / `select` / `textarea`** |

`.dragged` is `position: absolute` (`css/am-admin/console.less:128`), and the placeholder is
`li.placeholder` (min-height 171px). `onDrop` calls `sortChainData(originalIndex, item.index())`,
splicing the in-memory `authChainConfiguration` to match the new DOM order.

### `locator.dragTo()` — no

**It does not move a link.** Measured: the call completes without throwing in ~111 ms, leaves no
`.dragged` / `.placeholder` behind and `body.dragging` unset — i.e. the drag never started at all,
so there is nothing to clean up. Calling it twice in a row does not help either.

The cause is `delay: 100`. `dragTo` is one atomic call — hover, `mouse.down`, two moves,
`mouse.up` — with no pause between the down and the moves, so `delayMet` is still `false` when
`drag()` runs and it returns early (`jquery-sortable-0.9.13.js:266`). Confirmed directly: a hand-
rolled down/move/up that takes 58 ms total also fails, while the identical sequence with a 150 ms
pause after `mouse.down` succeeds.

### What does work

```js
/**
 * Drag the chain link at index `from` onto the slot at index `to`.
 *
 * jquery-sortable is configured with delay:100 (EditChainView.initSortable), so the drag only
 * arms 100ms after mousedown and every move before that is discarded — which is exactly why
 * locator.dragTo() cannot drive it. distance is 0, so the first move after the pause starts it.
 * The grab point must not be an input/select/textarea: groupDefaults.onMousedown refuses those,
 * so grabbing the link's criteria <select> silently does nothing.
 */
async function dragLink (page, from, to, { steps = 12, settle = 25 } = {}) {
    const items = page.locator("#sortableAuthChain li.chain-link");
    const start = await items.nth(from).locator(".panel-menu .btn-group button").first().boundingBox();
    const target = await items.nth(to).boundingBox();

    const x = start.x + start.width / 2;
    const y0 = start.y + start.height / 2;
    // aim past the destination's far edge so the placeholder is pushed all the way through it
    const y1 = to > from ? target.y + target.height - 4 : target.y + 4;

    await page.mouse.move(x, y0);          // position the cursor; mouse.down fires where it is
    await page.mouse.down();
    await page.waitForTimeout(150);        // > options.delay (100) — this line is the whole trick
    for (let i = 1; i <= steps; i++) {
        await page.mouse.move(x, y0 + ((y1 - y0) * i) / steps);
        await page.waitForTimeout(settle);
    }
    await page.mouse.up();
    await page.waitForTimeout(250);
}
```

- **A hover before `mouse.down` is required** only in the sense that `mouse.down` fires at the
  cursor's current position — the `mouse.move(x, y0)` is how you aim it. No separate `hover()` is
  needed, and no small "nudge" move before the travel is needed either.
- **One move after the pause is enough.** Measured: 1, 2, 3 and 12 intermediate moves all land the
  link correctly. 12 is kept above only as margin on a loaded machine; it costs ~700 ms per drag
  against ~310 ms for one move.
- **Grab point**: the handle button, `h3.media-heading` and `.panel-body .media` all work.
  `[data-select-criteria]` does **not** — `onMousedown` bails on a `<select>` and the drag never
  starts. That is also why a spec must not grab the link by its centre without checking what is
  there.
- **Viewport does not matter.** It works at the default 1280x720 even though the third link's
  bottom sits at y≈1027, well below the fold — 10/10.

### Reliability

| scenario | result |
| --- | --- |
| drag 0 → 2 (down), 1280x1400 | **10 / 10** |
| drag 0 → 2 (down), default 1280x720 | **10 / 10** |
| drag 2 → 0 (up) | **5 / 5** |
| adjacent swap 0 → 1 | **5 / 5** |
| `locator.dragTo()` | 0 / 2 |

**30 / 30 for the manual sequence.** It is a spec, not a future red build.

> One caveat, and it is the reason an earlier pass of this investigation wrongly recorded 3/8: the
> flakiness was entirely in the *harness*, not the drag. See §7.

### Is the new order visible immediately, and is it persisted

| question | answer |
| --- | --- |
| DOM order after drop | changed **immediately** — `h3.media-heading` order is the new order before any save |
| REST before save | **unchanged** — the drag is in-memory only |
| save | `[data-save-chain]` → `PUT .../chains/<name>` with `{authChainConfiguration}` → `Changes saved` |
| REST after save | matches the DOM order exactly (`PERSIST_REST_MATCHES_DOM` true) |
| after re-render | order and criteria both survive |

So the reorder **is** confirmable over REST as a second check:

```js
const chain = await (await request.get(
    `${realmRestBase(realmPath)}/realm-config/authentication/chains/${name}`,
    { headers: { "Accept-API-Version": "protocol=1.0,resource=1.0", iPlanetDirectoryPro: token } }
)).json();
expect(chain.authChainConfiguration.map((l) => l.module)).toEqual(["e2eModB", "e2eModC", "e2eModA"]);
```

`authChainConfiguration` is an ordered array of `{module, criteria, options}`; measured after
dragging A to the end: `[e2eModB:OPTIONAL, e2eModC:REQUISITE, e2eModA:REQUIRED]` — the criteria
travel with their link, they are not positional.

## 7. The stale-view trap, in its most expensive form

`page.goto()` to the hash the console is **already on** does not re-run the route, so the previous
attempt's unsaved DOM survives — and `waitFor` on `li.chain-link` passes instantly against it,
because those elements are still there. Reproduced deliberately:

```
STALE_AFTER_DRAG            ["e2eModB","e2eModC","e2eModA"]   drag succeeded
STALE_AFTER_SAME_HASH_GOTO  ["e2eModB","e2eModC","e2eModA"]   goto same hash: nothing re-rendered
STALE_AFTER_BOUNCE          ["e2eModA","e2eModB","e2eModC"]   list -> editor: real render, REST order
```

A loop that resets the chain over REST and then `goto`s the editor therefore drags a list that is
still in the *previous* attempt's order. Each drag still works perfectly, but the results read as a
3-cycle of "failures" — the first pass here recorded `3/8` and every one of the five "failures" is
exactly what dragging the previous result would produce. **A reorder spec that re-navigates between
assertions and does not force a re-render will look flaky and will not be.**

Bounce off the list route, and assert the starting order before measuring anything:

```js
async function openEditor (page, name) {
    await page.goto(H("authentication-chains"));
    await page.locator("#content h1", { hasText: /^Chains$/ }).waitFor();
    await page.goto(H(`authentication-chains/edit/${name}`));
    await page.locator("#content h1", { hasText: name }).waitFor();
    await page.locator("#sortableAuthChain li.chain-link").first().waitFor();
}
```

## 8. Criteria

`[data-select-criteria]` on each link is a **plain `<select class="form-control inline-block">`** —
there is no selectize on a rendered link (`li.chain-link .selectize-control` count is 0). So
`selectOption()` works directly, and `inputValue()` reads it back.

| option value | label |
| --- | --- |
| `REQUIRED` | Required |
| `OPTIONAL` | Optional |
| `REQUISITE` | Requisite |
| `SUFFICIENT` | Sufficient |

```js
await page.locator("#sortableAuthChain li.chain-link").nth(1)
    .locator("[data-select-criteria]").selectOption("SUFFICIENT");
```

Changing it is persisted **the same way as the reorder** — `selectCriteria` mutates the in-memory
`linkConfig` only; REST is unchanged until `[data-save-chain]`, which posts the whole
`authChainConfiguration`. One save carries both a reorder and a criteria change.

Side effects of a change, both immediate and useful as oracles:

- the link's footer re-renders (`renderArrows`): the pass arrow's class flips from
  `panel-arrow-down panel-arrow-success` to `panel-arrow-right panel-arrow-success` for
  `SUFFICIENT`. The footer *text* ("CONTINUE PASS") does not distinguish OPTIONAL from SUFFICIENT —
  assert on the class, not the text.
- `validateChain` re-runs and may raise a warning into `#chains #alertContainer`:
  `div.alert.alert-warning`, "Warning: Passing a SUFFICIENT module after the failing a REQUIRED
  module will continue through the chain and will not exit at that point. Consider using REQUISITE
  instead of REQUIRED." It fires when a REQUIRED link precedes a SUFFICIENT link and something
  follows it. **It does not disable saving** — only an empty chain does that.

## 9. Deleting a chain

Three paths, and they do not behave alike.

| path | control | message on success |
| --- | --- | --- |
| editor header | `.page-header [data-delete]` | **`Chain deleted successfully`** (info), then routes to the list |
| list row | `button[data-delete-chain][data-chain-name="<name>"]` | **silent** — oracle is the row detaching |
| list bulk | check boxes, then `[data-delete-chains]` | **silent** — oracle is the rows detaching |

All three show a BootstrapDialog confirmation (`showConfirmationBeforeAction`), with different
bodies:

| | title | body |
| --- | --- | --- |
| editor header | `Confirm Delete` | `Are you sure that you want to delete this Chain?` (capital C) |
| list row | `Confirm Delete` | `Are you sure that you want to delete this chain?` (lowercase c) |
| bulk, 1 | `Confirm Delete` | `Are you sure you want to delete the selected chain?` |
| bulk, >1 | `Confirm Delete` | `Are you sure you want to delete the selected chains?` |

| dialog part | selector |
| --- | --- |
| title | `.bootstrap-dialog .bootstrap-dialog-title` |
| body | `.bootstrap-dialog .bootstrap-dialog-message` |
| confirm | `.bootstrap-dialog .modal-footer button.btn-danger` ("Delete") |
| cancel | `.bootstrap-dialog .modal-footer button.btn-default` ("Cancel") |

Cancel on the editor keeps the chain and the hash — verified.

Removing a *link* (`li.chain-link [data-delete]`) has **no confirmation at all**: the `li` goes
immediately and `authChainConfiguration` is spliced in memory. Removing every link puts the editor
back into the empty state (call-to-action visible, `[data-save-chain]` disabled).

### `adminAuthModule` / `orgConfig` — the guard is dead code on this build

`AuthenticationService.chains.all` marks a chain `defaultConfig.adminAuthModule` /
`defaultConfig.orgConfig` when its `_id` equals `authenticationData[0].adminAuthModule` /
`.orgConfig`, and `ChainsTemplate` uses that to add `default-config-row`, `disabled` the checkbox
and `disabled` the row's delete button. `EditChainView.render:176` does the same for the header
button, adding `disabled` plus an explanatory popover.

**Neither ever fires here.** `GET /realm-config/authentication` returns those two keys nested under
`core`, not at the top level:

```
GET .../realms/root/realm-config/authentication
  -> { "core": { "orgConfig": "ldapService", "adminAuthModule": "ldapService" }, "accountlockout": …, … }
     top-level .adminAuthModule === undefined
```

so the comparison is against `undefined` and no chain is ever flagged. Confirmed in the console: a
fresh sub-realm has `core.adminAuthModule === core.orgConfig === "ldapService"`, and yet
`tr.sorted-chains.default-config-row` count is **0**, `ldapService`'s row checkbox and delete button
are both **enabled**, and the editor's `[data-delete]` for it carries class `btn btn-default` with
no `disabled`.

Two consequences for the spec:

- **`[data-select-all]` selects every chain in the realm, including `ldapService`.** It skips
  `:disabled` checkboxes, and none are disabled. Measured 5/5 rows selected. A spec that clicks
  select-all and then bulk-delete destroys the realm's default authentication chain. **Do not use
  select-all;** check the specific chains by name.
- Asserting "the default chain cannot be deleted" would assert a behaviour this build does not have.
  If the spec wants to pin the guard, it should pin the *absence* — assert `default-config-row` is
  0 — so the day the shape mismatch is fixed the spec says so.

**What the server does when you actually delete such a chain was not determined, deliberately** —
that is the situation the brief said to read rather than create, and creating it is how you stop
being able to log in. Only the console-side guard was inspected.

## 10. Messages

`#messages`, one div per notification; install `captureMessages()` from `common/xui-commons.mjs`
before the action (messages fade after ~2.5-3.5 s).

| event | text | class |
| --- | --- | --- |
| `[data-save-chain]` / `[data-save-settings]` | `Changes saved` | `alert-system alert-message alert alert-info` |
| delete from the editor header | `Chain deleted successfully` | `… alert alert-info` |
| duplicate name on the create form | `A Chain with the same name already exists` | `… alert alert-danger` |
| delete of a chain that is already gone | `Not Found` | `… alert alert-danger`, and the row stays |
| navigating to a chain that does not exist | `Not Found` | `… alert alert-danger` |
| **create succeeded** | *(silent)* | oracle is the route change to the editor |
| **delete from the list**, row or bulk | *(silent)* | oracle is the row detaching |

## 11. REST surface

Base as in `auth-commons.mjs`'s `realmRestBase(realmPath)`; all calls take
`Accept-API-Version: protocol=1.0,resource=1.0`.

| operation | call |
| --- | --- |
| create chain | `POST {base}/realm-config/authentication/chains?_action=create` body `{"_id":name}` → 201 |
| read chain | `GET {base}/realm-config/authentication/chains/{name}` |
| update chain | `PUT` same URL, body `{"authChainConfiguration":[…]}` |
| delete chain | `DELETE` same URL |
| list chains | `GET {base}/realm-config/authentication/chains?_queryFilter=true` |
| realm auth config | `GET {base}/realm-config/authentication` — `core.adminAuthModule`, `core.orgConfig` |

Two differences from the modules endpoints, both of which trip up code copied from 1.14:

- **A `GET` for a deleted chain is a clean `404`**, not the modules endpoint's 200-with-empty-`_id`.
  The `readModule` `_id` guard is not needed for chains — but do not assume the reverse either.
- **`_queryFilter=_id eq "x"` is `501 Not Implemented`** on the chains endpoint (it is what
  `AddModuleView` uses for modules). Existence must be decided from `_queryFilter=true` plus a
  membership check, or from the `404`.
- Duplicate create is `409 Unable to create SMS config: Service already exists`.

Also worth knowing: `DELETE` of a module a chain references answers **200** — the server allows it
and the chain keeps a dangling reference (`LinkView.getModuleDesciption` renders such a link with a
blank type). The *console's* module list disables both delete controls for a referenced module
(`NOTES-auth-modules.md` §6), so console and REST disagree; a chains spec should delete the chain
before the module, or let realm teardown take both.

Suggested split: **drive the console** for create, add-link, reorder, criteria and all three delete
flows. **Use REST** for realm lifecycle, for seeding modules and pre-built chains, and for reading
back what a console save persisted — the reorder assertion in particular is much stronger with the
REST read-back than with the DOM alone.

## 12. Idempotency and cleanup

Same shape as `xui-services.spec.mjs` and `xui-auth-modules.spec.mjs`: **give every test its own
realm**, created over REST with `uniqueRealmName` / `createRealm` from `common/realms-commons.mjs`
and registered for teardown *before* it exists. Reuse `createModule` from `common/auth-commons.mjs`
for the module instances a chain is built from — do not add second helpers for either.

A realm can be deleted with chains and modules still configured in it (verified), so no per-chain
cleanup is needed and no run can be affected by a previous one. A leftover chain collides on the
name — `409` over REST, and the console's create button stays disabled with
`A Chain with the same name already exists` — which is exactly what realm-per-test avoids.

Do **not** clean up by deleting chains from the list with `[data-select-all]`; see §9.

## 13. Not determined

- **What AM's server does when you delete a chain that is a realm's `adminAuthModule` or
  `orgConfig`.** Deliberately not exercised. The console-side guard was read and shown to be
  inert (§9); whether the SMS layer refuses the `DELETE` is unknown.
- **Whether the criteria popover (`[data-auth-criteria-info]`) renders its content correctly**, and
  the Settings tab's `PostProcessView` table. Neither is on the path this task describes; both were
  left alone.
- Why `page.fill()` on `#name` does not enable `[data-save]` but does on some other forms — a
  `.press("End")` after the fill sidesteps it (§3), so it was not isolated.

## 14. Restore

The instance was returned to its pristine state and re-confirmed after teardown:

```
REALMS_AFTER        ["null//"]        # the root realm alone
ROOT_CHAINS         ["amsterService","ldapService"]
ROOT_CORE           {"orgConfig":"ldapService","adminAuthModule":"ldapService"}
ADMIN_LOGIN_OK      true
```

Every scratch realm was deleted, `amadmin` login re-confirmed, and the root realm's chains and
`core` authentication configuration are unchanged. No chain or module was created, edited or deleted
outside a scratch realm, and no `adminAuthModule` or `orgConfig` was written.
