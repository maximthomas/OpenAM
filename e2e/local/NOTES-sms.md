# The SMS surface `xui-services.spec.mjs` drives

Source-read only — no container was started, no live AM was contacted. Everything below is from the
XUI sources, AM's Java SMS handlers, the recorded capture, `REQUESTS.md` and the spec itself. **No
schema payload was read into context**; every size below is measured (`wc -c` over `.response.body`).

This is the input to **task 2.11** — "serve the SMS schema and template responses the console
generates its forms from". The scope is `e2e/xui/xui-services.spec.mjs`, not the console's full
service-administration capability.

## Scope: the spec, not the console

The spec pins one service type, `baseurl`, in a scratch realm per test. Everything the console can
do with sub-schemas, collection services, or the other 17 types is out of scope except for one
incidental type (`dashboard`, see "The second type" below) and one incidental endpoint
(`_action=getAllTypes`, see "Sub-schemas").

The spec drives two distinct URL families and the stand-in must serve **both**:

| Family | Shape | Driven by |
|---|---|---|
| realm-scoped (console) | `/json/realms/root/realms/<realm>/realm-config/services/…` | the browser, via `fetchUrl.jsm` — `fetchUrl("/realm-config/…", {realm:"/e2e-svc-x"})` → `/realms/root/realms/e2e-svc-x/realm-config/…` |
| realm-as-query (fixture) | `/json/realm-config/services/…?realm=/<realm>` | `e2e/common/services-commons.mjs`, over Playwright's `APIRequestContext` |

They are the same resources reached two ways. `capture/README.md` finding 2 already records that the
two `getCreatableTypes` bodies came back byte-identical (1 355 B each), differing only in
`request.path` and the presence of `request.query.realm`.

Every call below carries `Accept-API-Version: protocol=1.0,resource=1.0`. There is no exception —
`ServicesService.js` hardcodes that header on all eleven of its calls, and `services-commons.mjs`
mirrors it (`const API_VERSION = "protocol=1.0,resource=1.0"`).

## Endpoint table

`V` = verbatim-servable: a pure static description of a service, byte-returnable from the capture
whatever the server's state. `S` = stateful: the server has to model something to answer it.

Sizes are the **response body** in bytes as captured (the capture files wrap each in a
`{request, response}` envelope, so the on-disk file is larger; both are given where they differ
materially).

### Console-driven (browser)

| # | Method | Path | `_action` | Used for | Body B | V/S |
|---|---|---|---|---|---|---|
| 1 | `GET` | `…/realms/{realm}/realm-config/services` | — (`_queryFilter=true`) | the service list's rows (`_id` → `data-service-id`, `name` → row text) | 197 | **S** |
| 2 | `POST` | `…/realms/{realm}/realm-config/services` | `getCreatableTypes` (`&forUI=true`) | the create form's type dropdown; also gates the list's Add button | 1 355 | **S** |
| 3 | `POST` | `…/realm-config/services/baseurl` | `schema` | generates the form (create *and* edit) | **876** | **V** |
| 4 | `POST` | `…/realm-config/services/baseurl` | `template` | the create form's starting values; decides which fields are visible | 100 | **V** |
| 5 | `POST` | `…/realm-config/services/baseurl` | `getAllTypes` | sub-schema types → decides whether a tab bar is drawn. Returns `{"result":[]}` | 13 | **V** |
| 6 | `POST` | `…/realm-config/services/baseurl` | `create` | persists the new service; `201` | 179 | **S** |
| 7 | `GET` | `…/realm-config/services/baseurl` | — | the edit form's values, and `_type.name` for its `<h1>` | 179 | **S** |
| 8 | `PUT` | `…/realm-config/services/baseurl` | — | persists the edit | 181 | **S** |
| 9 | `DELETE` | `…/realm-config/services/baseurl` | — | removes it. Returns `{"success":true}` | 16 | **S** |
| 10 | `POST` | `…/realm-config/services/dashboard` | `schema` | generates the *second* form in the rebuild test | 201 | **V** |
| 11 | `POST` | `…/realm-config/services/dashboard` | `template` | that form's starting values | 26 | **V** |

### Fixture-driven (`APIRequestContext`, realm as query parameter)

| # | Method | Path | `_action` | Used for | Body B | V/S |
|---|---|---|---|---|---|---|
| 12 | `POST` | `/json/realm-config/services` | `getCreatableTypes` (`&forUI=true&realm=…`) | the spec's own oracle — `creatableServiceTypes()`; resolves `serviceTypeName`, picks the second type, and counts the dropdown | 1 355 | **S** |
| 13 | `POST` | `/json/realm-config/services/baseurl` | `create` (`&realm=…`) | `createService()` — the premise for the edit and delete tests; `201` | 179 | **S** |
| 14 | `GET` | `/json/realm-config/services/baseurl` | — (`?realm=…`) | `readService()` — asserts the write reached the server. **`200` and `404`**; `404` body is `{"code":404,"message":"Not Found","reason":"Not Found"}` (55 B) | 179 / 55 | **S** |

**14 endpoint/action pairs.** They match `REQUESTS.md` lines 91–104 exactly; that table was derived
independently and agrees.

## Verbatim vs stateful — the decision this hangs on

**Five calls are verbatim.** All of them are the `_action=` descriptions:

- `baseurl?_action=schema` (876 B)
- `baseurl?_action=template` (100 B)
- `baseurl?_action=getAllTypes` (13 B)
- `dashboard?_action=schema` (201 B)
- `dashboard?_action=template` (26 B)

Nothing in these depends on realm state. `capture/README.md` already classifies them `V` (rows 13
and 14 of its resource table) and records the general finding that SMS descriptions are
realm-independent. A stand-in can return these four files byte-for-byte from the capture, keyed on
`(type, action)`, ignoring the realm entirely.

**Nine calls are stateful**, and they are all small — the largest stateful body is
`getCreatableTypes` at 1 355 B. The state to model is one thing: *which service types exist in
which realm*. Concretely:

- **create** (#6, #13) must store the posted values **merged over the template**, not the posted
  values alone. The console sends only `{extensionClassName, fixedValue}` (see
  `showOnlyRequiredAndEmpty` below) and the spec then asserts
  `created.source === "REQUEST_VALUES"` — a value the console never sent. The template is where it
  comes from.
- **GET** (#7, #14) must return the stored values wrapped as
  `{"_id":"", "_type":{"_id":"baseurl","collection":false,"name":"Base URL Source"}, …}`, and must
  `404` before the create and after the delete. `readService()` returns `null` on `404` and the
  delete tests assert exactly that.
- **PUT** (#8) must persist and echo. The spec reloads the page afterwards and re-reads the field.
- **DELETE** (#9) must remove it, so that #1, #2 and #7 all change their answers.
- **the listing** (#1) must gain and lose the `baseurl` row.
- **`getCreatableTypes`** (#2, #12) must gain and lose the `baseurl` *option* — inversely to #1.

`capture/README.md`'s "Known limits" records that whether `getCreatableTypes` is state-dependent
"is not determined", because both recordings happened before the create. **It is determined now**,
from AM's source and from the spec — see the next section. That known limit can be closed.

### One consistency constraint across three stateful endpoints

The display name `"Base URL Source"` appears in three places and the spec cross-checks all three:

- `getCreatableTypes` → `result[].name` — the spec reads `serviceTypeName` from here;
- the listing → `result[].name` — asserted as the row's text;
- `GET baseurl` → `_type.name` — asserted as the edit form's `<h1>` (via
  `ServicesService.instance.get`, which reads `response[1][0]._type.name`).

They must agree. Serving the first from the capture and inventing the other two would fail.

## The `getCreatableTypes` rule

**Confirmed from AM's source.** `SmsRouteTree.handleAction` dispatches `getCreatableTypes` to
`readTypes(context, NOT_CREATED_SINGLETONS, forUI)`
(`openam-core-rest/src/main/java/org/forgerock/openam/core/rest/sms/tree/SmsRouteTree.java:286-296`).
The predicate (same file, `:559-581`):

- if the type is a **collection** (`collection: true`) → always included;
- if it is a **singleton** → the handler does a READ of that singleton in the current realm.
  `404` → included (creatable). A successful read → **excluded**, unless the read carries a
  non-null `dynamic` attribute that is an empty map.

`forUI=true` only suppresses types on the `hiddenFromUI` list (`:316-317`); it does **not** do the
filtering. Nor does the console: `ServicesService.type.getCreatables` merely
`_.sortBy(response.result, "name")` — client-side sorting, no filtering. The filtering is entirely
server-side.

All 19 types in the captured answer have `collection: false`, so for this spec the collection branch
never fires.

### What the stand-in must recompute on every call

> On every `getCreatableTypes` request, return the full 19-entry type list **minus every type the
> named realm currently has an instance of** — recomputed from live state at request time, never
> cached and never served as a fixed list.

That is the whole rule. It is load-bearing three times over:

1. `createService` in the fixture gives a realm `baseurl`; the test
   *"the create form stops offering a type the realm already has"* then asserts
   `offered` does **not** contain `baseurl`, that `offered.length > 0`, and that the rendered
   dropdown has **exactly `offered.length` options** (18) with no `baseurl` among them. A fixed
   19-entry list fails on all three.
2. The spec's own file header names this as the reason each test gets a fresh realm: a leftover
   service "removes the option the create test clicks, and makes that test fail on its second run
   having passed on its first". The stand-in must reproduce that coupling, or the spec stops testing
   what it says it tests.
3. The spec's `test.describe` comment says so outright: *"A local server that returned a fixed list
   would pass the create test and fail the one below it."*

The inverse must hold too: after the console's own create (#6), the very next listing (#1) must
contain `baseurl` and the very next `getCreatableTypes` (#2) must not — the create test re-opens the
list at its end and asserts the row is there.

### The second type — an ordering constraint, easy to miss

The rebuild test picks its second type with
`offered.find((candidate) => candidate._id !== SERVICE_TYPE)` over the **raw, unsorted** `result`
array (`services-commons.mjs` returns `.result` untouched). In the capture the first entry is
`dashboard`, which is why `dashboard`'s schema and template are the only other payloads recorded.

So: **whatever type the stand-in lists first must be one whose `_action=schema` and
`_action=template` it can serve.** Keep `dashboard` first and the capture already covers it. Reorder
the list and the rebuild test asks for a schema that does not exist.

## Request ordering, per flow

Requests inside one `Promise.all` are issued together; they are listed indented under the call that
fans them out. `∥` marks a parallel group.

### Rendering the service list — `ServicesView.render`

```
∥ 1  GET  …/realm-config/services?_queryFilter=true          (rows)
∥ 2  POST …/realm-config/services?_action=getCreatableTypes&forUI=true   (gates the Add button)
```

`validateAddButton` disables Add and shows a popover when the creatables list is **empty**, so the
stand-in must never answer `{"result":[]}` here for these realms.

### Create

```
  0  (fixture) POST /json/realm-config/services?_action=getCreatableTypes&forUI=true&realm=…
                  — givenRealm() resolves serviceTypeName from this, once per worker

  1  GET  …/realm-config/services?_queryFilter=true            ⎫ ServicesView.render
  2  POST …/realm-config/services?_action=getCreatableTypes    ⎭ ∥

  3  POST …/realm-config/services?_action=getCreatableTypes    NewServiceView.render — fills the
                                                               selector. >1 type ⇒ selectize;
                                                               exactly 1 ⇒ auto-selected

     — operator picks "baseurl" ⇒ NewServiceView.selectService ⇒ getInitialState —
  4  POST …/realm-config/services/baseurl?_action=schema       ⎫ ∥
  5  POST …/realm-config/services/baseurl?_action=template     ⎭

     — operator clicks Create —
  6  POST …/realm-config/services/baseurl?_action=create       201; body is ONLY
                                                               {extensionClassName, fixedValue}

     — console routes to the edit form ⇒ EditSchemaComponent.render —
  7  POST …/realm-config/services/baseurl?_action=schema       ⎫
  8  GET  …/realm-config/services/baseurl                      ⎬ ∥ (7+8 are one inner Promise.all
  9  POST …/realm-config/services/baseurl?_action=getAllTypes  ⎭    inside the outer one)

 10  (fixture) GET /json/realm-config/services/baseurl?realm=…  the assertion

 11  GET  …/realm-config/services?_queryFilter=true            ⎫ list re-opened
 12  POST …/realm-config/services?_action=getCreatableTypes    ⎭ ∥
```

`_action=schema` is fetched **twice** in this flow — once by `getInitialState` for the create form,
once by `instance.get` for the edit form. There is no client-side cache: `AbstractDelegate.serviceCall`
does no memoisation, it hands straight to `ServiceInvoker.restCall`, which sets
`Cache-Control: no-cache` on the request. Every one of these goes out on the wire, every time.

The **rebuild** test adds, after step 5: another `schema` + `template` pair for `dashboard`, then a
third `schema` + `template` pair for `baseurl` again when the operator changes their mind back —
so the stand-in sees the same `(type, action)` pair three times in one page and must answer
identically each time.

### Edit

```
  0  (fixture) POST …?_action=getCreatableTypes…  +  POST …/baseurl?_action=create&realm=…

     — page.goto(#…/services/edit/baseurl) ⇒ EditSchemaComponent.render —
  1  POST …/realm-config/services/baseurl?_action=schema       ⎫
  2  GET  …/realm-config/services/baseurl                      ⎬ ∥
  3  POST …/realm-config/services/baseurl?_action=getAllTypes  ⎭

     — operator clicks Save —
  4  PUT  …/realm-config/services/baseurl                      body = values.extend(getData()).raw,
                                                               i.e. _id, _type AND all four
                                                               properties — not just the edited one

  5  (fixture) GET /json/realm-config/services/baseurl?realm=…

     — page.reload() ⇒ cold boot ⇒ render again —
  6  POST …?_action=schema  ⎫
  7  GET  …/baseurl         ⎬ ∥
  8  POST …?_action=getAllTypes ⎭
```

No routing after save; the console raises its own `changesSaved` message (`EventManager` →
`config.messages.AppMessages.changesSaved`). AM's `PUT` answer carries no message, so the stand-in
does not have to supply one — it only has to succeed.

### Delete — three routes, three orderings

**(a) from the edit form** (`EditSchemaComponent.onDelete`) — the only route that routes and the only
one whose dialog uses `console.common.confirmDeleteSelected`:

```
  1-3  schema ∥ GET ∥ getAllTypes            (edit form renders)
       — confirm dialog —
  4    DELETE …/realm-config/services/baseurl
       — routes back to the list —
  5    GET  …/realm-config/services?_queryFilter=true       ⎫ ∥
  6    POST …/realm-config/services?_action=getCreatableTypes ⎭
  7    (fixture) GET …/baseurl?realm=…   ⇒ must be 404
```

**(b) from a list row** (`ServicesView.onDeleteSingle` → `deleteServices`) — uses
`console.services.list.confirmDeleteSelected`, re-renders in place, posts no message:

```
  1-2  GET listing ∥ POST getCreatableTypes
       — dialog opened and CANCELLED: no request at all —
       — dialog opened and confirmed —
  3    DELETE …/realm-config/services/baseurl
       — this.rerender() —
  4    GET  …/realm-config/services?_queryFilter=true       ⎫ ∥
  5    POST …/realm-config/services?_action=getCreatableTypes ⎭
  6    (fixture) GET …/baseurl?realm=…   ⇒ must be 404
```

The cancel path issuing **no** request is asserted (the row must still be there, and `readService`
must still find it).

**(c) from the toolbar** (`ServicesView.onDeleteMultiple`) — identical wire sequence to (b); the only
difference is that `remove()` takes an array and issues one `DELETE` per checked id, via
`Promise.all`. With one row checked that is one `DELETE`. Same dialog key as (b).

## Which type, and what its schema requires

**`baseurl`** (Base URL Source). The spec chose it because it is inert and has the smallest form.

Its schema (876 B) is a flat `{"type":"object","properties":{…}}` with **four `string` properties,
all `"required": true`**:

| Property | `propertyOrder` | Notable |
|---|---|---|
| `source` | 100 | `enum` of 5: `FIXED_VALUE`, `FORWARDED_HEADER`, `X_FORWARDED_HEADERS`, `REQUEST_VALUES`, `EXTENSION_CLASS`, with matching `options.enum_titles`. Renders as a **second selectize** on the create page — which is why every type-selector locator in the spec is scoped to its own form group |
| `fixedValue` | 200 | plain string |
| `extensionClassName` | 300 | plain string |
| `contextPath` | 400 | plain string |

No `title` at the root, no nested objects. `JSONSchema.isCollection()` is
`_.every(properties, p => p.type === "object")` — every property here is `"string"`, so
`isCollection()` is **false**. That is what puts both forms on the `FlatJSONSchemaView` path and
what makes the edit form render the `.panel-footer` the spec's `[data-save]` lives in.

The template (100 B) is
`{"contextPath":"/{{CONTEXT}}","extensionClassName":null,"fixedValue":null,"source":"REQUEST_VALUES"}`.

### Why the create form sends exactly two keys

`FlatJSONSchemaView.render` with `showOnlyRequiredAndEmpty: true` computes
`_.intersection(schema.getRequiredPropertyKeys(), values.getEmptyValueKeys())`
(`FlatJSONSchemaView.js:74-79`). `getEmptyValueKeys` treats numbers and booleans as non-empty and
otherwise defers to `_.isEmpty` (`JSONValues.js:134-143`). Against the pair above:

- required = all four;
- empty = `extensionClassName` (`null`), `fixedValue` (`null`) — `"/{{CONTEXT}}"` and
  `"REQUEST_VALUES"` are non-empty strings;
- intersection = **`[extensionClassName, fixedValue]`**.

Those two are shown; the other two are *built and hidden* (`removeUnrequiredProperties()` removes
nothing here, since all four are required — the visibility comes from `addDefaultProperties`). The
spec asserts both halves: the request body's keys are exactly
`["extensionClassName", "fixedValue"]`, **and** `root[contextPath]` exists in the DOM with count 1
and is hidden.

**The template is therefore load-bearing beyond being scenery.** Change any of those four values
between `null` and non-`null` and the create form's field set changes with it, and the spec's
key assertion fails. Serve it verbatim.

`dashboard`, the incidental second type, has a single `array` property `assignedDashboard`
(`required: true`) and a template of `{"assignedDashboard":[""]}`. `_.isEmpty([""])` is `false`, so
it has **no** required-and-empty property and its create form renders entirely hidden — which is why
the rebuild test asserts only that a `.form-group` is *attached*, not visible.

## Sub-schemas

**Not reached — with one exception that must still be served.**

The spec never opens a sub-schema screen. `SubSchemaListView.js`, `NewServiceSubSchemaView.js` and
`EditServiceSubSchemaView.js` are never loaded, and these six endpoints are **never called**:

- `POST …/services/{type}?_action=getCreatableTypes` (the sub-schema-scoped one, no `forUI`)
- `POST …/services/{type}?_action=nextdescendents`
- `POST …/services/{type}/{sub}?_action=schema`
- `POST …/services/{type}/{sub}?_action=template`
- `GET` / `PUT` / `DELETE` / `POST ?_action=create` on `…/services/{type}/{sub}[/{instance}]`

They are unreachable for `baseurl`, which has no sub-schema types. `EditSchemaComponent` only builds
a `SubSchemaListComponent` for the `subschema` tab, and that tab only exists when
`getSubSchemaTypes()` came back non-empty (`EditSchemaComponent.js:55-78`, `:119-155`). The spec
pins this from the other side by asserting `#content .nav-tabs` has count `0`.

**The exception:** `EditSchemaComponent.render` fans out
`_([this.getInstance, this.getSubSchemaTypes]).compact().map(call => call())`
(`EditSchemaComponent.js:161-168`), and `EditServiceView` supplies both. So
`POST …/realm-config/services/baseurl?_action=getAllTypes` **is issued on every edit-form render**,
including the one the create test lands on. It must be served, and it must answer
`{"result":[]}` — 13 bytes, in the capture, verbatim. Answering anything non-empty draws a tab bar
and fails the edit test; failing to answer it at all leaves the outer `Promise.all` pending and the
edit form never renders, which fails every test that reaches an edit form.

So: **one sub-schema-adjacent endpoint, serving a constant empty list. Nothing else.**

## Error shape on a rejected create

**The spec does not exercise one.** There is no rejected-create test, no `alert-danger` assertion,
and no malformed or duplicate create anywhere in the file — the only two message assertions are both
`alert-info` (`changesSaved`, on save and on delete-from-the-edit-form). The stand-in does not have
to produce a create rejection for this spec.

For completeness, the path that would consume it: `NewServiceView.onCreateClick`'s rejection handler
calls `Messages.addMessage({ response, type: Messages.TYPE_DANGER })` with the raw jQuery failure,
and commons' `Messages` reads `responseJSON.message` off it. The only error body the capture holds
is the `404` probe: `{"code":404,"message":"Not Found","reason":"Not Found"}` — AM's standard CREST
error shape, `{code, message, reason}`. That is the shape to use *if* a rejection is ever needed, but
nothing here asks for it.

## Payload sizes

Measured with `wc -c` over `jq -cj '.response.body'`; the on-disk capture file wraps this in a
`{request, response}` envelope and is larger.

| Payload | Body B | File B |
|---|---|---|
| `services?_action=getCreatableTypes` (realm-scoped) | **1 355** | 3 051 |
| `services?_action=getCreatableTypes` (realm-as-query) | **1 355** | 3 051 |
| `baseurl?_action=schema` | **876** | 2 105 |
| `dashboard?_action=schema` | 201 | 983 |
| `services?_queryFilter=true` | 197 | 946 |
| `baseurl` GET / `?_action=create` (realm-scoped) | 179 | 863 / 1 028 |
| `baseurl` PUT | 181 | 1 132 |
| `baseurl?_action=template` | 100 | 763 |
| `baseurl` GET `404` | 55 | 682 |
| `dashboard?_action=template` | 26 | 683 |
| `baseurl` DELETE | 16 | 626 |
| `baseurl?_action=getAllTypes` | 13 | 655 |

**Largest schema payload: `baseurl?_action=schema`, 876 bytes** (2 105 B on disk with its envelope).
**Largest payload of any kind in this surface: `getCreatableTypes`, 1 355 bytes** — which is
stateful, not a schema.

This surface is small. The whole SMS scope of this spec is ~3.4 KB of distinct response bodies
(3 378 B, counting the two byte-identical `getCreatableTypes` answers once), of which the five
verbatim descriptions are 1 216 B. Contrast the authentication schemas at 23 988 B
and the global-config authentication schema at 29 044 B (`capture/README.md`, rows 10 and 11) — the
service schemas the console generates its forms from are by far the *smallest* SMS documents in the
capture, and `baseurl` was chosen for exactly that reason.

## Undetermined

Nothing blocking. Two things worth recording:

- **The literal `/{{CONTEXT}}` in the template and in every stored `contextPath`** is a capture
  placeholder, not AM's real answer — `capture/README.md`'s placeholder table maps it to "the servlet
  context, without its leading slash", with D14 making it configurable and defaulting to `openam`.
  The stand-in must substitute it the same way it does everywhere else. The spec never reads
  `contextPath`'s value (it only asserts the field exists and is hidden on create, and is visible on
  edit), so this cannot fail the spec — but serving the raw `{{CONTEXT}}` string would be wrong in
  the same way it would be wrong anywhere else.
- **`hiddenFromUI` is not enumerated here.** `forUI=true` suppresses types on that list
  (`SmsRouteTree.java:316-317`), but which types are on it is set at route-registration time and was
  not traced. It does not matter for the stand-in: the captured 19-entry answer is already the
  post-`forUI` list, so serving that list (minus what the realm has) reproduces the filter without
  reimplementing it. It would matter only if the stand-in ever had to answer `forUI=false`, which
  nothing in this spec does.
