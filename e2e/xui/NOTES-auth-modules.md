# Authentication module administration — what a Playwright spec can rely on

Findings verified empirically against `http://openam.example.org:8080/openam` (OpenAM
16.2.0-SNAPSHOT) on 2026-08-11, with six throwaway Chromium/node runs as `amadmin`. Every run worked
inside its own scratch realm created and deleted over REST. Nothing under the root realm's
authentication configuration was created, edited or deleted, and no realm's `adminAuthModule` or
`orgConfig` was touched. See [Restore](#9-restore) for the confirmation.

Companion to `xui-services.spec.mjs`, which drives the other schema-generated admin form. Read the
differences in §3 and §5 before assuming the service spec's shape transfers — several parts do not.

## 0. Console session realm — the safety premise, confirmed

`idFromSession`, called from inside the logged-in console page, and `getSessionInfo` both answer
`"realm":"/"` for `amadmin`. The console admin session authenticates against the **root** realm, so a
sub-realm's authentication configuration cannot lock the console out. This is what makes a scratch
sub-realm a safe place to create and delete modules.

## 1. Routes

`config/routes/admin/RealmsRoutes.js:93-119`. The realm path is `encodeURIComponent`-encoded, exactly
as `realmHash()` in `common/realms-commons.mjs` already builds it.

| screen | hash | helper |
| --- | --- | --- |
| list | `#realms/%2Fscratch/authentication-modules` | `realmHash(realmPath, "authentication-modules")` |
| create | `#realms/%2Fscratch/authentication-modules/new` | `realmHash(realmPath, "authentication-modules/new")` |
| edit | `#realms/%2Fscratch/authentication-modules/<type>/edit/<name>` | `realmHash(realmPath, \`authentication-modules/${type}/edit/${name}\`)` |

The edit route carries **both** the type id and the instance name, in that order. The type segment is
load-bearing: see §7.

## 2. The two module types — and the candidates that lost

Chosen: **`securid` (SecurID)** and **`httpbasic` (HTTP Basic)**. Both are 2-property schemas, both are
creatable in a fresh realm, both are deletable, and both are inert (§8) — but they generate *visibly
different* forms, which is the point of testing two:

| type | generated form | third-party widget |
| --- | --- | --- |
| `securid` | two plain `input[type=text]` | none — 0 selectize controls |
| `httpbasic` | a **hidden native `<select>` decorated by selectize** plus one `input[type=text]` | 1 selectize control |

So the pair pins "the form is generated per type" at the widget level, and `httpbasic` covers the
`JSONEditor.plugins.selectize` path (`models/Form.js:39`) that a build migration of the shimmed
non-AMD libraries can break, while `securid` is the control case with no such dependency.

Candidates considered and rejected, with the tradeoff:

| type | leaves | why not |
| --- | --- | --- |
| `datastore`, `federation`, `sae` | 1 | a single field is too little to prove a form was generated; `datastore` also shares a name with the realm's stock `DataStore` instance |
| `deviceidsave` | 3 | genuinely safe and adds a checkbox, but all its widgets are JSONEditor-native, so it proves strictly less than `httpbasic` |
| `anonymous` | 4 | the widest widget spread (text, number, checkbox, array) — **rejected on risk**: an Anonymous module is the one candidate where an accidental chain reference means credential-free login |
| `membership` | 4 | good spread (enum + array + 2 numbers) but it writes user profiles if ever exercised, and 4 fields for no extra widget class over `httpbasic` |
| `ldap`, `certificate`, `oauth2`, `adaptiverisk` | 21-47 | far too large |

One caveat on `httpbasic`: its `backendModuleName` enum is derived from the realm's existing
`ldap`/`datastore` instances — a fresh realm gives `["LDAP","DataStore"]`. Verified it does **not**
change when `securid`/`httpbasic` instances are added. A spec that also created an `ldap` or
`datastore` module would grow that enum.

## 3. Create form (`AddModuleView.js`, `AddModuleTemplate.html`)

| what | selector | notes |
| --- | --- | --- |
| title | `#content h1` | "New Module" |
| name | `#newModuleName` (also `[data-module-name]`) | hand-written, `required`, `autofocus` |
| type container | `[data-module-type]` | a bare `<div>`; `SelectComponent` renders into it |
| type control | `[data-module-type] .selectize-input` | click to open |
| type options | `[data-module-type] .selectize-dropdown-content .option` | 34 on this instance |
| chosen item | `[data-module-type] .selectize-input .item` | |
| **create** | `[data-save]` | label "Create" — **not** `[data-create]` as in the service spec |
| cancel | `.panel-footer a.btn-default` | href back to the list route |

**Both create-form fields are hand-written.** There is no JSONEditor on this screen at all — no
`root[...]` inputs, and no per-type schema is fetched here. That is the biggest structural difference
from `NewServiceView`, which generates the create form from the chosen type's schema.

### Choosing a type: by text, never by value

`SelectComponent` (`common/components/SelectComponent.jsm`) stamps each option's `data-value` with
`__selectize_key`, which is **the option's index in the array**, not the type id. Measured:
`SecurID=28`, `Membership=17`, `HTTP Basic=13`, `Device Id (Save)=9`, `Anonymous=2`. The native
`<select>` has no `name` and no `id`, and its `.value` is that same index.

So select by the visible display name:

```js
await page.locator("[data-module-type] .selectize-input").click();
await page.locator("[data-module-type] .selectize-dropdown-content .option",
    { hasText: /^SecurID$/ }).first().click();
```

`labelField` is `name` (the type's display name) and `searchFields` is `["name"]`, so typing the
display name into the control also filters to it.

### When the create button enables

`validateModuleProps` (`AddModuleView.js:28`) requires a non-empty name **containing no space** and a
chosen type. Bound to `change`/`keyup` on `[data-module-name]` and `change` on `[data-module-type]`.

| state | `[data-save]` disabled |
| --- | --- |
| fresh form | yes |
| name filled, no type | yes |
| name filled + type chosen | **no** |
| name containing a space | yes, plus a danger message |

Robust ordering: **fill the name first, choose the type last.** The type's `onChange` re-reads the
name straight out of the DOM, so the name needs no synthetic event of its own. (Whether
`page.fill()` alone fires the handler was not isolated — choosing the type last makes it moot.)

## 4. Edit form (`EditModuleView.jsm`, `EditModuleViewTemplate.html`)

| what | selector | notes |
| --- | --- | --- |
| title | `#content h1` | the **module name** (dynamic title) |
| subtitle | `#content h4` | the type's display name, e.g. "SecurID" |
| form container | `#tabpanel` | `models/Form.js` builds a raw JSONEditor into it |
| save | `[data-save]` | "Save Changes", **enabled from first render** |
| revert | `[data-revert]` | "Revert" → `form.reset()` |
| delete | — | **there is none.** Delete is list-only (§6) |
| tabs | `#content .nav-tabs` | never rendered on this instance — see below |

Every field here is **JSONEditor-generated** with `root[...]` naming. Unlike `NewServiceView`, `Form`
is constructed without `showOnlyRequiredAndEmpty`, so every property is rendered *and visible*.

### The two types' fields

| type | field | selector | widget / default |
| --- | --- | --- | --- |
| `securid` | `serverConfigPath` | `input[name="root[serverConfigPath]"]` | text, `/usr/openam/config/openam/auth/ace/data` |
| `securid` | `authenticationLevel` | `input[name="root[authenticationLevel]"]` | text (integer schema still renders as `type=text`), `0` |
| `httpbasic` | `backendModuleName` | `select[name="root[backendModuleName]"]` — **hidden** | enum `LDAP`\|`DataStore`, default `LDAP` |
| `httpbasic` | (its control) | `#tabpanel .selectize-input` + `#tabpanel .selectize-dropdown-content .option` | the visible input inside `.selectize-control` has **no** `name` |
| `httpbasic` | `authenticationLevel` | `input[name="root[authenticationLevel]"]` | text, `0` |

Read the hidden `<select>` for assertions (`.inputValue()` works on it), drive the selectize control
for input — the same split the service spec uses for its type selector:

```js
await page.locator("#tabpanel .selectize-input").click();
await page.locator("#tabpanel .selectize-dropdown-content .option", { hasText: /^DataStore$/ })
    .first().click();
expect(await page.locator("select[name='root[backendModuleName]']").inputValue()).toBe("DataStore");
```

**Field order is not stable.** `securid` rendered `serverConfigPath, authenticationLevel` on one load
and `authenticationLevel, serverConfigPath` after a reload — the schema's property order comes from an
unordered JSON object. Address fields by `name`, never by index.

### Tabs — nothing is hidden behind one

`EditModuleView` imports `bootstrap-tabdrop` and calls `.tabdrop()`, but the tab bar is guarded by
`{{#if schema.grouped}}`, and `grouped` is `_.every(properties, isObjectType)`
(`SMSServiceUtils.js:132`). **None of the 34 module types on this instance is grouped** — checked
against every one — so `.nav-tabs` is never rendered, `renderTab` never fires, and the whole form is
built into `#tabpanel` by the `!grouped` branch. Verified at runtime for both chosen types
(`#content .nav-tabs` count 0).

No field a spec needs is behind a tab. Worth asserting the tab bar is absent, so the day a grouped
type appears the spec says so rather than silently editing one group: with `grouped`, `renderTab`
**empties `#tabpanel`** and rebuilds a Form for that group alone, and `save()` posts only the current
group's data.

## 5. Edit flow — what persists, and how to assert it

Save issues `PUT .../modules/<type>/<name>` with `form.data()` and stays on the same hash.

| step | observed |
| --- | --- |
| message | `Changes saved` — `#messages` div, class `alert-system alert-message alert alert-info` |
| hash after save | unchanged (`.../securid/edit/e2eSecurid`) |
| REST read-back | `{"serverConfigPath":"/tmp/e2e-edited-path","authenticationLevel":7,...}` |
| after a full reload | `root[authenticationLevel]=7`, `root[serverConfigPath]=/tmp/e2e-edited-path` |
| `httpbasic` read-back | `{"authenticationLevel":5,"backendModuleName":"DataStore",...}`, survives reload |

To assert survival, re-navigate and re-read the inputs — but see the stale-view trap in §7: waiting on
`#tabpanel .form-group` alone will read the *previous* module's form.

## 6. Delete flow — per-row and bulk, both confirmed, both silent

`ModulesTemplate.html` rows are `tr[data-module-name="<name>"]`, carrying `data-module-type` and
`data-module-chains`. Scope row selectors with `tr` — the create form's name input also has
`[data-module-name]`.

| what | selector |
| --- | --- |
| row | `tr[data-module-name="e2eSecurid"]` |
| row delete | `tr[...] [data-delete-module]` |
| row checkbox | `tr[...] [data-select-module]` |
| bulk delete | `[data-delete-modules]` (in `.btn-toolbar.page-toolbar`) |
| add module | `.page-toolbar a.btn-primary` — an `<a>`, **no data attribute**, text "Add Module" |
| type column | third `<td>`, the type's `typeDescription` |

Both the checkbox and the row delete button are `disabled` when the module is referenced by a chain.
Modules this spec creates are unreferenced, so both are enabled — verified.

Checking a row adds class `selected` to the `<tr>` and enables `[data-delete-modules]`; after the
list re-renders the bulk button is disabled again.

**Both paths show a BootstrapDialog confirmation**, with different bodies:

| | title | body | keys |
| --- | --- | --- | --- |
| per-row | `Confirm Delete` | `Are you sure that you want to delete this module?` | `console.common.confirmDeleteText` + `console.authentication.common.module` |
| bulk | `Confirm Delete` | `Are you sure you want to delete the selected module?` (`_plural` for >1) | `console.authentication.modules.confirmDeleteSelected` |

| dialog part | selector |
| --- | --- |
| title | `.bootstrap-dialog .bootstrap-dialog-title` |
| body | `.bootstrap-dialog .bootstrap-dialog-message` |
| confirm | `.bootstrap-dialog .modal-footer button.btn-danger` ("Delete") |
| cancel | `.bootstrap-dialog .modal-footer button.btn-default` ("Cancel") |

Cancel keeps the row and closes the dialog — verified. **Neither delete posts a message**; the only
oracle is the row leaving the list (`waitFor({ state: "detached" })`).

Unrelated but adjacent: `[data-check-before-edit]` (the "module is in a chain, are you sure" dialog)
is only stamped on the **pencil icon**, and only for modules already in a chain. The name link gets a
`check-before-edit` *class* that nothing binds. Neither fires for modules this spec creates.

## 7. Traps

### Stale view on hash navigation — the one that will bite

`page.goto()` to a different hash does **not** reload the document, and the previous view's DOM stays
until the new one renders. Reproduced deliberately: from the `securid` edit form, `goto` the
`httpbasic` edit hash, then wait only on `#tabpanel .form-group` —

```
B_immediate_h1      staleSecurid
B_immediate_fields  ["root[serverConfigPath]","root[authenticationLevel]"]   <- wrong module
B_settled_fields    ["root[backendModuleName]",null,"root[authenticationLevel]"]
```

Always wait on a **view-specific** signal, i.e. the title carrying the module's own name:

```js
await page.goto(H(`authentication-modules/${type}/edit/${name}`));
await page.locator("#content h1", { hasText: name }).waitFor();
await page.waitForSelector("#tabpanel .form-group");
```

The same hazard applies to the very first navigation after login: without
`openAdminConsole`'s wait on `#toggleCardList .page-toolbar`, the landing route still in flight
overwrites the `goto` and the create form never appears — reproduced as a 30 s timeout. Use
`openAdminConsole` from `common/xui-commons.mjs`, do not hand-roll the login.

### Selectors that differ from the service spec

Create button is `[data-save]` (not `[data-create]`); the edit form has **no** delete button; the
"Add Module" control is an `<a>` with no data attribute; and the create form has no generated fields.

## 8. Inertness — verified, not assumed

Method: snapshot, create `securid` + `httpbasic` instances in a scratch realm, snapshot again, compare.
Baseline noise was measured first — two identical reads with nothing changed in between must compare
equal — because the naive comparison gives **false positives**: `_queryFilter` result order is
unstable and `POST /json/authenticate` returns a fresh `authId` JWT nonce every call. Normalising
(sort the module/chain lists, drop `authId`) makes both stable.

| observed | result |
| --- | --- |
| root realm modules, chains, `realm-config/authentication` | identical |
| scratch realm chains, `realm-config/authentication` | identical |
| `POST /json/authenticate` (root realm), callbacks offered | identical modulo `authId` |
| `POST /json/authenticate?realm=/scratch`, callbacks offered | identical modulo `authId` |
| `amadmin` login | still returns a token |
| changed keys | `[]` |

So an unreferenced module instance changes no chain, no realm authentication configuration, and no
existing login flow.

One honest caveat: the instance does become reachable as an **explicit** authentication index —
`POST /json/authenticate?realm=/scratch&module=e2eSecurid` answers 200 with that module's callbacks.
That is a path a caller must ask for by name; it alters no default, no chain and no existing flow, and
the realm is deleted at teardown.

## 9. Idempotency — a leftover collides on the name

Unlike services, where `getCreatableTypes` hides types the realm already has, `getAllTypes` is
**unfiltered**: 34 types before and after creating instances, byte-identical list, and `SecurID` still
offered in the dropdown with two `securid` instances already in the realm. Modules are named
instances, so two of the same type coexist happily (`idemA:securid`, `idemB:securid`).

A leftover therefore does **not** change what the create form offers — it collides on the name:

| path | behaviour |
| --- | --- |
| console, same name, **any** type | `modules.exists()` queries `_id` across all types first → danger message `Authentication instance already exists.`, stays on `/new`, **no POST issued**. Verified with name `e2eSecurid` + type `Membership` |
| REST, same name **same** type | `409` `Unable to create SMS config: Service already exists` |
| REST, same name **different** type | **`201`** — the server allows it, and the list then shows two rows with the same name under different types |

The console is stricter than the server. REST fixture setup can create a collision the console would
refuse.

**Cleanup that makes a re-run identical:** give every test its own realm, created over REST and
registered for teardown *before* it exists, exactly as `xui-services.spec.mjs` does. A realm can be
deleted with modules still configured in it — verified — so no per-module cleanup is needed and no
test can be affected by a previous run. Use `createRealm` / `removeRealm` / `uniqueRealmName` from
`common/realms-commons.mjs`; do not add a second realm helper.

## 10. REST surface — what fixtures should use instead of the console

Realm base for a child of root is `/json/realms/root/realms/<name>` (`fetchUrl` maps `/x` →
`/realms/root/realms/x`). All calls take `Accept-API-Version: protocol=1.0,resource=1.0`.

| operation | call | use for |
| --- | --- | --- |
| create realm / delete realm | `realms-commons.mjs` | fixture, teardown |
| create module | `POST {realm}/realm-config/authentication/modules/{type}?_action=create` body `{"_id":name}` → 201 | fixture for the edit and delete tests |
| read module | `GET {realm}/realm-config/authentication/modules/{type}/{name}` | assert what the console persisted — **but not that it is gone**, see the addendum below |
| update module | `PUT` same URL | fixture |
| delete module | `DELETE` same URL | teardown |
| list modules | `GET {realm}/realm-config/authentication/modules?_queryFilter=true` | assert create/delete outcome |
| exists | `GET {realm}/realm-config/authentication/modules?_queryFilter=_id eq "name"&_fields=_id` | the check the console itself makes |
| all types | `POST {realm}/realm-config/authentication/modules?_action=getAllTypes` | resolve a type id to its display name for the dropdown |
| schema | `POST {realm}/realm-config/authentication/modules/{type}?_action=schema` | assert the form matches the schema |
| template | `POST {realm}/realm-config/authentication/modules/{type}?_action=template` | the defaults a created instance starts with |

Suggested split: **drive the console** for create (type selection, enablement, routing to the edit
form), edit (field fill, save, message, reload) and delete (both dialogs, row removal). **Use REST**
for realm lifecycle, for seeding the module the edit and delete tests operate on, and for reading back
what a console save persisted.

The type segment genuinely selects the instance: `GET`/`PUT` with a mismatched type is `404`, and a
wrong-type `PUT` changes nothing — verified.

### Addendum — a `GET` cannot tell you a module was deleted

*Found while implementing task 1.14, not during the discovery pass above. It was the only failure in
the spec's first run, and it presents as a delete that did not happen.*

A `GET` for a name that **never existed** is a `404`. A `GET` for a name that existed and was
**deleted** is a `200`, carrying the type's template defaults under an **empty `_id`**:

```
GET .../modules/securid/neverExisted   404  {"code":404,"reason":"Not Found"}
GET .../modules/securid/deletedName    200  {"serverConfigPath":"/usr/openam/config/openam/auth/ace/data",
                                             "authenticationLevel":0,"_id":""}
```

The delete did happen — `_queryFilter` answers `result: []` and the name is absent from
`?_queryFilter=true` — so only the read disagrees, and it disagrees with plausible-looking
configuration rather than with an error.

Two consequences for anything asserting a module or chain is gone:

- **the existence oracle is `_queryFilter=_id eq "<name>"`**, the check the console itself makes (the
  `exists` row above), not a status code from a `GET`;
- a `readModule`-style helper must treat a mismatched `_id` as absence. `common/auth-commons.mjs`
  does this, and `moduleExists` there wraps the query filter — task 1.15 inherits both.

## 11. Messages

`#messages`, one div appended per notification. Install `captureMessages()` from
`common/xui-commons.mjs` **before** the action; the component removes a message after ~2.5-3.5 s.

| event | text | class |
| --- | --- | --- |
| save on the edit form | `Changes saved` | `alert-system alert-message alert alert-info` |
| duplicate name on create | `Authentication instance already exists.` | `... alert alert-danger` |
| space in the name | `Spaces are not allowed in a module's name` | `... alert alert-danger` |
| **create succeeded** | *(silent)* | oracle is the route change to the edit form |
| **delete succeeded**, either path | *(silent)* | oracle is the row leaving the list |

Create routes to `.../authentication-modules/<type>/edit/<name>` on success — wait on that hash and
then on `#content h1` carrying the name.

## 12. Not determined

- **A mismatched type in the edit hash does not show the `notFound` message.** Navigating to
  `.../httpbasic/edit/<a securid module>` rendered a form with the previous module's fields and `h1`
  set to the requested name, instead of `console.authentication.modules.notFound` — even after a full
  reload of the list route first. `EditModuleView` keeps `this.data.values` from its previous render
  and the template's `{{#if values}}` stays truthy, but the error branch builds no `Form`, so that
  alone does not explain the `#tabpanel .form-group` that was present. **Do not use a wrong-type URL
  as a negative-case oracle**; REST is unambiguous (404).
- Whether `page.fill("#newModuleName", …)` alone enables the create button, without a synthetic
  `keyup`. Choosing the type last sidesteps it (§3).

## 13. Restore

The instance was returned to its pristine state and re-confirmed:

```
REALMS_REMAINING   ["Lw"]            # base64url("/") — the root realm alone
E2E_REALMS_LEFT    []
ROOT_MODULES_FINAL ["Amster:amster","DataStore:datastore","Federation:federation","HOTP:hotp",
                    "LDAP:ldap","OATH:oath","SAE:sae","WSSAuthModule:wssauth"]
ROOT_CHAINS_FINAL  ["amsterService","ldapService"]
```

All five scratch realms were deleted, `amadmin` login re-confirmed after teardown, and the root
realm's modules, chains and `realm-config/authentication` are byte-identical (normalised) to the
pre-run snapshot. No module was created, edited or deleted outside a scratch realm, and no
`adminAuthModule` or `orgConfig` was touched.

## 14. Follow-ups for task 1.15 (authentication chains)

*Written while implementing 1.14. A chain is assembled from module instances, so 1.15 inherits the
fixtures below and every trap in §7.*

### What it inherits, and the one API sharp edge

`common/auth-commons.mjs` holds the REST fixtures. Three things about it are worth knowing before
reusing it:

| helper | note for chains |
| --- | --- |
| `realmRestBase(realmPath)` | exported deliberately — chains live under the same `/realm-config/authentication/` base, so a chains fixture should build on this rather than re-deriving the `/realms/root/realms/x` mapping |
| `moduleExists(token, request, realmPath, name)` | answers about the **name alone, across every type** — it is `AddModuleView`'s own pre-flight query, not a `(type, name)` lookup. A chains spec that creates several modules in one realm and wants "is *this* one gone" needs `readModule`, which is type-scoped |
| `readModule` | returns `null` when the returned `_id` does not match the name asked for. That is not defensive coding — see the §10 addendum; without it a deleted instance reads back as present, with plausible configuration |

`createModule(token, request, realmPath, type, name)` with no `values` creates the instance from the
type's template, which is exactly what the console's create form does — that is the right fixture for
"a realm with modules to build a chain out of".

### Traps that carry over

- **A module a chain references cannot be deleted from the list.** §6: both the row's delete button
  and its checkbox are rendered `disabled`. 1.14's modules are unreferenced so both are enabled and it
  never meets this. A chains spec will: delete the chain before the module, or let realm teardown take
  both. Do not wait on a delete control being enabled without accounting for it.
- **The stale-view trap (§7) is not module-specific.** It is a property of hash routing in this
  console, so it applies to every chain route too. Wait on a view-specific signal — a title carrying
  the chain's own name — never on a selector the previous view also had.
- **`renderedFieldNames` in `xui-auth-modules.spec.mjs` is flat-scalar only.** Its `^root\[(.*)\]$`
  capture is greedy; an array or nested-object property renders `root[x][0]` and would be reported as
  the property `x][0`. Both 1.14 types are flat. Strip trailing index groups before reusing it.
- **`httpbasic`'s `backendModuleName` enum is realm-derived**, from `ConfiguredModuleInstances`
  (`amAuthHTTPBasic.xml`) — it lists the realm's own `ldap`/`datastore` instances. A spec that adds
  such instances to a shared realm changes it. 1.14 derives the value from the served schema rather
  than naming `LDAP`/`DataStore`, so it tolerates this; a chains spec should not reintroduce literals.

### Left undone in 1.14, deliberately

- **The type column is asserted with `toContainText` on the whole `<tr>`** (`xui-auth-modules.spec.mjs`,
  create test), so it matches text from any cell. It is sound only by an accident of casing —
  `"e2eSecurid"` does not contain `"SecurID"`. Scoping it to the third `<td>` would say what it means.
  Not changed in 1.14 because the AM instance was down when the fix was identified and a positional
  cell selector could not be re-run; `xui-services.spec.mjs` has the same shape, so changing one
  should probably change both.
