# Task 8.2 - the lodash 3 -> 4 API scan, and what every call site became

**Tracked record of task 8.2.** Group 8's `tasks.md` entry for 8.2 is "re-scan both codebases for
lodash 3 APIs beyond those three, since the count came from a targeted search". The deliverable is
therefore this record - the method, the derived removal list, the per-site table with its outcomes,
and an explicit boundary - not only the code changes it drove.

It began (in task 8.1) as a measurement record produced without modifying anything. Task 8.2 kept
the measurement, re-verified it independently against the post-8.1 trees, and then acted on it.
Sections marked **[8.1]** describe the state before this task's edits; the per-site table (S3) and
the outcome and boundary sections (S3.4, S12) describe what the code is now.

> **Path note.** All paths below are relative to `/home/maxim/Documents/_projects/forgerock/`.
> The `openspec-commons` checkout holds only `openspec/`.

## 0. Preflight

| Check | Result |
|---|---|
| `git -C OpenAM branch --show-current` | `features/openam-ui-migration` |
| `git -C commons branch --show-current` | `features/ui-migration` |
| `openam-ui-ria/src/main/js/libs/lodash-3.10.1-min.js` | present, 50,543 B; `require()` reports `VERSION = 3.10.1` |
| `openam-ui-ria/node_modules/lodash/package.json` | present, `version = 4.18.1` |
| `openam-ui-ria/vite.config.js` | present (268,843 B); aliases `lodash` **and** `underscore` to the vendored 3.10.1 file (lines 3041, 3058) |

The alias is the reason this inventory exists at all: today the browser runs 3.10.1 for *both*
identifiers, and lodash 4.18.1 is only the build toolchain's copy. Confirmed on the built bundle -
`target/compiled/assets/main-*.js` contains the string `3.10.1`. Task 8.3 flips that alias; 8.1 and
8.2 have to make the sources survive the flip.

No container, Docker or AM instance was started.

---

## 1. Method - and why it is not a grep for three names

The figure this task exists to correct ("25 call sites of `_.pluck`, `_.contains`, `_.where`",
recorded in the `//peerDependencies-lodash` note of both commons `package.json` files) is what a
grep for three names produces. Three independent passes were run instead, each able to find things
the others cannot.

### 1.1 Pass 1 - derive the removal list from the two libraries on disk

Both libraries are on disk and both are UMD, so both `require()` cleanly under Node. The removal
list is the set difference of their exported keys - derived, not remembered, and not taken from any
changelog or blog post.

```
node -e '
  const l3 = require("<abs>/openam-ui-ria/src/main/js/libs/lodash-3.10.1-min.js");
  const l4 = require("<abs>/openam-ui-ria/node_modules/lodash");
  const keys = o => new Set([...Object.getOwnPropertyNames(o), ...Object.keys(o)]);
  const k3 = keys(l3), k4 = keys(l4);
  console.log([...k3].filter(k => !k4.has(k)).sort().join("\n"));'
```

`l3.VERSION === "3.10.1"`, `l4.VERSION === "4.18.1"`. 228 keys in 3, 313 in 4, 197 shared.

**In 3, not in 4 - 31 names:**

```
all  any  backflow  callback  collect  compose  contains  detect  findWhere  foldl  foldr
include  indexBy  inject  methods  modArgs  object  padLeft  padRight  pairs  pluck
restParam  select  sortByAll  sortByOrder  support  trimLeft  trimRight  trunc  unique  where
```

**Correction, found in 8.2's review pass: this command is structurally blind to one class of
removal.** It diffs the keys of the lodash *function object*, which is only the top-level API. The
**chain wrapper** is a separate object, and diffing it too:

```
const p3 = Object.getOwnPropertyNames(l3.prototype);
const p4 = Object.getOwnPropertyNames(l4.prototype);
console.log(p3.filter(k => !p4.includes(k)).sort().join(" "));
```

yields the same 31 names **plus one more - `run`**, lodash 3's alias for `value()`, removed from the
lodash 4 wrapper. It has no top-level `_.run`, so neither the key diff above nor the `_.`-anchored
grep in S12.1 can see it, and it was live at `NavigationHelper.jsm:65`. **The derived removal list
is 32 names, not 31**; the 32nd is reachable only through a chain. See S1.6.

### 1.2 Pass 2 - enumerate the calls with a parser, not a regex

`@babel/parser` (already in `openam-ui-ria/node_modules`, JSX-capable) parses every `.js`, `.jsm`
and `.jsx` file in both trees and every `CallExpression` whose callee is a `MemberExpression` is
recorded with its **argument count and argument node types**. Two callee shapes are collected:

* `direct` - `_.name(...)`
* `chained` - `_(x).a().name(...)` or `_.chain(x).a().name(...)`, detected by walking the
  member/call chain down to its root identifier and testing it for `_`

Counts: **272 files / 694 lodash calls** in `openam-ui-ria/src/main/js` (excluding `libs/`),
**65 / 258** in `commons/ui/commons`, **14 / 85** in `commons/ui/user`, **16 / 32** in
`commons/ui/mock`. **Zero parse failures**, so the enumeration is complete over those files.

Why the parser rather than `grep -o '_\.\w*('`:

* a plain grep misses every **chained** call. Six of the removed-API sites are chained
  (`.pluck("_id")`, `.pairs()`, `.object()`) and a name-anchored grep on `_.` finds none of them.
* argument *count* and *type* is what separates a safe `_.filter(coll, fn)` from the
  redefined-in-4 `_.filter(coll, "prop", value)`. Only a parser gives that.
* line numbers for chained calls are taken from the **property** node, not the CallExpression,
  so `.uniq(JSON.stringify)` is reported at the line it is written on and not at the line the
  chain starts.

A separate AST pass looks for `MemberExpression` on `_` with a removed name that is **not** in
callee position, i.e. the function used as a value. It found exactly one:
`AM org/forgerock/openam/ui/user/UserModel.js:172` -
`return _.spread(_.partial(_.contains, this.uiroles))(arrayify(roles));`.
A `_.contains(` grep does not match that line.

Two cross-checks confirmed nothing was lost: a superset grep for `\.<removedName>\(` over the same
files (105 hits) reconciles exactly to the AST result once `Promise.all`, Backgrid `this.callback`,
jQuery `.select()` and the service-layer `.all()` methods are removed; and every `import` of lodash
in both trees was checked - 136 files write `import _ from "lodash"` and 14 write a bare
`import "lodash"` (side-effect only, using the global `_` the AMD shim installs), across 170 files
that name it; the commons AMD sources list `"lodash"` in 20 `define()` dependency arrays and bind
it to `_` there too. There are **no** named imports and **no** local alias other than `_`, so `_.`
is a sound anchor.

### 1.3 Pass 3 - APIs present in both majors that mean different things

Steps 1 and 2 cannot see these by construction. Rather than work from a remembered list, the two
loaded libraries were **differentially probed**: for every name used in the sources that exists in
both majors (76 names), the same call was evaluated against `l3` and `l4` over a corpus of argument
tuples shaped like the ones this codebase actually passes (arrays, plain objects, collections of
objects, pair arrays, `(coll, "prop", value)`, `(coll, fn, thisArg)`, `(x, true)`, path strings,
method names), and any mismatch in JSON-serialised result or thrown-error class was flagged. Then
every flagged name was re-probed with the exact expressions found at the call sites.

That is how `_.clone(x, true)`, `_.capitalize`, `_.escape`, `_.merge(..., customizer)`,
`.flatten(true)`, `.uniq(iteratee)`, the `(prop, value)` shorthand and the trailing `thisArg`
turned up. None of them is `_.invoke` or `_.zipObject`, the two the brief names.

Both named suspects were confirmed rather than taken on trust:

| probe | lodash 3.10.1 | lodash 4.18.1 |
|---|---|---|
| `_.invoke([{f(){return 1}},{f(){return 2}}], "f")` | `[1, 2]` | `undefined` |
| `_.object([["a",1],["b",2]])` | `{a:1, b:2}` | *not a function* |
| `_.zipObject([["a",1],["b",2]])` | `{a:1, b:2}` | `{}` (re-measured in 8.2; **S1.3 first recorded `{"a,1": undefined, ...}`, which is wrong for 4.18.1** - either way it is silent and wrong) |
| `_.fromPairs([["a",1],["b",2]])` | *not a function* | `{a:1, b:2}` |

### 1.4 Verifying the replacements instead of reasoning about them

Every proposed replacement in the table was **evaluated against both loaded libraries** and its
results compared, not argued about. 42 comparisons were run. **39 came back identical**, and all
three that did not are the *existing* expressions rather than proposed replacements
(`_.merge(..., customizer)` twice, `_.omit(array, predicate)` once) - see S5. The `.pairs()` /
`.flatten(true)` / `.uniq(JSON.stringify)` replacements were additionally proved end to end by
patching them into the **generated** `target/npm/esm` tree and re-running the commons Vitest suite
with lodash 4 aliased in (S8.1).

---

### 1.5 The 8.2 re-verification - the same three passes, re-run independently

Task 8.2's first action was to re-derive the whole inventory from scratch against the **post-8.1**
trees, before changing anything, and to report the result beside 8.1's figures rather than assume
they still held.

**Pass 1 re-run** - the set difference of exported keys, same command as S1.1:

| quantity | 8.1 recorded | 8.2 re-measured | agrees? |
|---|---|---|---|
| `l3.VERSION` / `l4.VERSION` | 3.10.1 / 4.18.1 | 3.10.1 / 4.18.1 | yes |
| keys in 3 / in 4 / shared | 228 / 313 / 197 | 228 / 313 / 197 | yes |
| names removed in 4 | 31 | 31 | yes |
| the 31 names themselves | S1.1 list | byte-identical | yes |

**Pass 2 re-run** - a fresh `@babel/parser` walk of all four trees, recording direct (`_.name(...)`)
and chained (`_(x).…name(...)`) callees, non-callee references to `_`, and computed access on `_`.
**367 files, 1069 lodash member-calls, zero parse failures.**

| quantity | 8.1 recorded | 8.2 re-measured (pre-edit) | agrees? |
|---|---|---|---|
| sites on the three names in `tasks.md` | 28 calls + 1 reference | **0** | yes - 8.1 fixed them all |
| sites on removed APIs beyond the three | 18 | **18** | yes, file-and-line identical |
| sites on redefined APIs | 44 | **44** | yes, file-and-line identical |
| non-call references to a removed name | 1 (`UserModel.js:172`) | **0** | yes - 8.1 fixed it |
| computed access (`_["contains"]`, `_[expr]`) | not separately reported | **0**, all file types | - |

**No disagreement to reconcile.** The 8.2 re-scan reproduces 8.1's inventory exactly. The three
missed-class hypotheses the task was told to test were each checked and each came back empty or
already-covered:

* **computed access** - `_["contains"](…)` or `_[someExpr]`: a dedicated AST branch plus a `grep -rn '_\['`
  over every file type in all three trees. **Zero hits.**
* **a chained `_(x).contains(…)` form** - covered by construction: the chained-callee branch is how
  4 of the 18 removed sites (`.pairs()`, `.object()`) and 8 of the 44 redefined ones
  (`.flatten(true)`, `.uniq(…)`, `.invoke("render")`, `.pick(pred)`, the chained `thisArg` maps)
  were found at all. A name-anchored `_\.` grep finds none of them.
* **a lodash call inside a Handlebars helper or a template** - real category, already covered.
  Handlebars templates are `.html` and cannot call JavaScript: a grep for `_\.[a-zA-Z]` across all
  233 `.html` files in the three trees returns **zero**. Helpers are registered *in `.js` files*,
  which the parser reads - and one of the 18 removed-API sites is literally inside one
  (`CMN util/UIUtils.js:383`, the `.pairs()` in `Handlebars.registerHelper('checkbox', …)`).

**Soundness of `_` as the anchor**, re-checked: across the three trees, 136 files write
`import _ from "lodash"`, 14 write a bare side-effect `import "lodash"`, and 20 AMD `define()`
arrays bind `"lodash"` to `_`. There are **no** named imports from lodash and no local alias other
than `_`.

**Pass 3 re-run** - every replacement family was re-evaluated against both libraries loaded from
disk before it was written, not after. All 15 families came back `SAME` under 3.10.1 and 4.18.1;
the measurements are in S5.1.

**These three passes agreed with 8.1 exactly - and they were still not sufficient.** A review pass
over the finished diff found **two whole classes of redefined API that the method above cannot
see**, worth 8 further defective sites. They are described in S1.6, and the passes that find them
are now part of the method. The agreement in the tables above is therefore evidence that the scan
is *reproducible*, not that it is *complete*: three passes reproducing each other is exactly what a
shared blind spot looks like.

### 1.6 Pass 4 and Pass 5 - the two classes the first three passes could not see

Both were found by reviewing the finished diff rather than by re-running the scan, which is the
point: a method that cannot express a defect will keep agreeing with itself. Both are now mechanical.

**Pass 4 - the wrapper prototype, not just the top-level API.** As recorded in S1.1, diffing
`Object.getOwnPropertyNames(_.prototype)` finds `run` in addition to the 31 top-level names.
One site: `NavigationHelper.jsm:65`.

**Pass 5 - methods that stop being chainable.** lodash 4 turned a group of methods from
chain-*continuing* into chain-*terminating*: in an implicit `_(x)` sequence they return the
unwrapped value instead of the wrapper. The name still exists and takes the same arguments, so
neither a key diff nor an argument-shape check notices. Derived, not remembered - for every method
shared by both prototypes, ask whether `_([1,2,3])[m](fn)` still returns a wrapper:

```
const wraps = (lib, m) => { const r = lib([1,2,3])[m](function () { return 1; });
                            return !!r && typeof r.value === "function"; };
shared.filter(m => wraps(l3, m) && !wraps(l4, m))
```

**11 names: `each  eachRight  forEach  forEachRight  forIn  forInRight  forOwn  forOwnRight
invoke  sample  times`.** Any implicit chain that *continues* after one of them throws under
lodash 4. Four sites, five calls - all four verified by execution against both libraries:

| site | expression | under lodash 4 |
|---|---|---|
| `AM .../jsonSchema/GroupedJSONSchemaView.js:102` | `_(x).map(…).map(…).each(…).value()` | `….value is not a function` |
| `AM .../admin/services/global/RealmsService.js:64` | `_(data.result).each(…).sortBy("path").value()` | `….sortBy is not a function` |
| `AM .../common/components/TabComponent.js:48, 49` | `_(options.tabs).each(…).each(…).value()` | `….each is not a function` |
| `AM .../common/util/NavigationHelper.jsm:56 -> 65` | `_(…).filter().sortBy().take().forEach(…).run()` | `….run is not a function` |

Note that S3 row `GroupedJSONSchemaView.js:101` **already recorded** that "the following `.each`
throws" - and the fix stopped at line 101 anyway. The observation was in the table; the pass that
would have made it actionable was not.

**A third gap, in Pass 2 rather than Pass 1.** Pass 2 classified `_.pick`/`_.omit` by the *AST node
type* of the second argument (S1.2: "argument count and type is what separates a safe call from a
redefined one"). That is blind when the predicate arrives as an **identifier** - a parameter, or an
imported iteratee - because the node is an `Identifier`, not a `FunctionExpression`. lodash 4
dropped predicate support entirely, so these fail **silently**, returning the unfiltered object:

| site | reached from | measured divergence |
|---|---|---|
| `AM .../common/models/JSONSchema.js:238` | `removeUnrequiredProperties()` <- `FlatJSONSchemaView.js:77` | l3 `{a,c}` / l4 `{a,b,c}` - non-required properties stop being removed |
| `AM .../common/models/JSONValues.js:155` | `JSONEditorView.js:141` | l3 `{user,other}` / l4 `{user,password:"",other}` - **empty password fields stop being stripped and are submitted to the server** |
| `AM .../jsonSchema/GroupedJSONSchemaView.js:95` | imported `iteratees/emptyProperties` | l3 drops the empty pair / l4 keeps both |

The check is now "can this argument be a function at runtime", not "is it a function literal":
every `_.pick`/`_.omit` whose second argument is not a string or array literal is listed for manual
resolution. Over the four trees that flags **11 candidates**; 4 are the new `omitByPredicate`
helper's own safe fallback and the two methods it fixed, and the other 7 resolve to literal key
lists (`tabs[i].attr`, `filtered`, `watchedProperties`, `collectionPropertiesKeys`) - confirmed by
reading each caller, not by shape.

---

## 2. Counts, and where they disagree with the recorded figure

### 2.1 The three names in `tasks.md`

| API | AM | commons/commons | commons/user | commons/mock | total |
|---|---:|---:|---:|---:|---:|
| `_.pluck` | 7 | 0 | 0 | 0 | **7** |
| `_.contains` | 14 (+1 non-call reference) | 4 | 0 | 0 | **18 (+1)** |
| `_.where` | 3 | 0 | 0 | 0 | **3** |
| | | | | | **28 calls, 29 sites** |

**This disagrees with the recorded 25 by +3 (+4 counting the reference), and the disagreement is
not reconciled away.** The likeliest cause is that the earlier count scanned only
`openam-ui-ria/src/main/js` and missed the four commons `_.contains` sites, or counted `_.pluck`
without its three chained forms in `ResourcePage.js`. Both figures are reproducible from this file:
`_.contains` alone is 18 calls in 2 repos.

### 2.2 Beyond the three, still fully removed from lodash 4

| API | AM | commons/commons | commons/user | commons/mock | total | lodash 4 name |
|---|---:|---:|---:|---:|---:|---|
| `_.object` | 2 | 1 | 2 | 0 | **5** | `_.fromPairs` (**not** `_.zipObject`) |
| `_.pairs` | 0 | 5 | 0 | 0 | **5** | `_.toPairs` |
| `_.findWhere` | 2 | 0 | 2 | 0 | **4** | `_.find` |
| `_.include` | 2 | 0 | 0 | 0 | **2** | `_.includes` |
| `_.any` | 1 | 0 | 0 | 1 | **2** | `_.some` |
| | | | | | **18** | |

The brief expected "ten or so"; the measured figure is **18** (17 excluding `commons/ui/mock`,
which is outside the two named trees but is in the same reactor and breaks the same way).

### 2.3 Beyond the three *again*: same name, different meaning

Invisible to a name-difference scan and to any grep. **44 sites.**

| class | AM | commons/commons | commons/user | total |
|---|---:|---:|---:|---:|
| `_.clone(x, true)` - deep flag ignored in 4 | 1 | 8 | 0 | **9** |
| trailing `thisArg` - dropped in 4 | 0 | 4 | 7 | **11** |
| `_.pick`/`_.omit(obj, predicate)` - `pickBy`/`omitBy` in 4 | 7 | 1 | 0 | **8** |
| `(coll, "prop", value)` shorthand - gone in 4 | 6 | 0 | 0 | **6** |
| `_.invoke(collection, ...)` - `invokeMap` in 4 | 2 | 0 | 0 | **2** |
| `_.capitalize` - lower-cases the tail in 4 | 2 | 0 | 0 | **2** |
| `_.escape` - stops escaping `` ` `` in 4 | 0 | 2 | 0 | **2** |
| `.uniq(iteratee)` - `uniqBy` in 4 | 0 | 2 | 0 | **2** |
| `.flatten(true)` - shallow only in 4 | 0 | 1 | 0 | **1** |
| `_.merge(..., customizer)` - `mergeWith` in 4 | 1 | 0 | 0 | **1** |
| | **19** | **18** | **7** | **44** |

### 2.4 Total

**90 call sites + 1 non-call reference = 91.** 46 on removed APIs, 44 on redefined ones,
1 reference. Against the 25 the peer-range note asserts, that is **3.6x**.

---

## 3. The per-call-site table

Column `group` says whether the row is one of the three names in `tasks.md` (`named 3`) or beyond
them (`beyond`). Column `both-major` answers: does the proposed replacement return the same value
under lodash 3.10.1 **and** 4.18.1 - verified by evaluation against the two loaded libraries, not
reasoned. Column `silent` answers: with the *obvious* rewrite in place under lodash 4, does the
code compile, run and return the wrong value? Column `test today` names the test that actually
executes the line; `None` is the honest and most common answer.

File prefixes: `AM ` = `OpenAM/openam-ui/openam-ui-ria/src/main/js/`,
`CMN ` = `commons/ui/commons/src/main/js/org/forgerock/commons/ui/common/`,
`USR ` = `commons/ui/user/src/main/js/org/forgerock/commons/ui/user/`,
`MCK ` = `commons/ui/mock/src/main/js/org/forgerock/mock/ui/`.

| file | line | exact expression | API | repo | group | proposed replacement | both-major | silent | test today |
|---|---:|---|---|---|---|---|---|---|---|
| `CMN components/ChangesPending.js` | 49 | `this.data = _.extend(defaults, _.clone(args, true));` | _.clone(x,true) | commons | beyond | `_.cloneDeep(x)` | yes | YES - deep flag ignored, shallow copy returned | None |
| `CMN components/ChangesPending.js` | 57 | `this.data.changes = _.clone(this.data.watchedObj, true);` | _.clone(x,true) | commons | beyond | `_.cloneDeep(x)` | yes | YES - deep flag ignored, shallow copy returned | None |
| `CMN components/ChangesPending.js` | 89 | `this.data.changes = _.clone(this.data.watchedObj, true);` | _.clone(x,true) | commons | beyond | `_.cloneDeep(x)` | yes | YES - deep flag ignored, shallow copy returned | None |
| `CMN components/ChangesPending.js` | 91 | `this.data.undoCallback(_.pick(_.clone(this.data.watchedObj, true), this.data.watchedProperties));` | _.clone(x,true) | commons | beyond | `_.cloneDeep(x)` | yes | YES - deep flag ignored, shallow copy returned | None |
| `CMN components/ChangesPending.js` | 101 | `this.data.changes = _.clone(changes, true);` | _.clone(x,true) | commons | beyond | `_.cloneDeep(x)` | yes | YES - deep flag ignored, shallow copy returned | None |
| `CMN components/ChangesPending.js` | 109 | `this.data.watchedObj = _.clone(this.data.changes, true);` | _.clone(x,true) | commons | beyond | `_.cloneDeep(x)` | yes | YES - deep flag ignored, shallow copy returned | None |
| `CMN components/ChangesPending.js` | 124 | `var isChanged = _.some(this.data.watchedProperties, function (prop) {` | trailing thisArg | commons | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no in the ESM build (strict mode -> TypeError); YES in the AMD build (sloppy mode, `this` becomes the global) | None |
| `CMN components/ChangesPending.js` | 140 | `var val1 = _.clone(obj1[property], true),` | _.clone(x,true) | commons | beyond | `_.cloneDeep(x)` | yes | YES - deep flag ignored, shallow copy returned | None |
| `CMN components/ChangesPending.js` | 141 | `val2 = _.clone(obj2[property], true),` | _.clone(x,true) | commons | beyond | `_.cloneDeep(x)` | yes | YES - deep flag ignored, shallow copy returned | None |
| `CMN components/Messages.js` | 79 | `msg.message = _.escape(msg.message);` | _.escape | commons | beyond | `_.escape(s).replace(/`/g, "&#96;")` | yes | YES but cosmetic - backtick no longer escaped | None |
| `CMN components/Messages.js` | 137 | `+ "'><i class='fa " + alertIcon + "'></i><span class='message'>" + _.escape(this.list[0].message)` | _.escape | commons | beyond | `_.escape(s).replace(/`/g, "&#96;")` | yes | YES but cosmetic - backtick no longer escaped | None |
| `CMN components/Navigation.js` | 180 | `this.data.admin = _.contains(Configuration.loggedUser.uiroles, "ui-admin");` | _.contains | commons | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `CMN components/Navigation.js` | 300 | `_.each(navObj.urls, function(obj){` | trailing thisArg | commons | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no in the ESM build (strict mode -> TypeError); YES in the AMD build (sloppy mode, `this` becomes the global) | None |
| `CMN components/navigation/filters/RoleFilter.js` | 37 | `&& _.contains(Configuration.loggedUser.uiroles, link.role);` | _.contains | commons | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `CMN main/AbstractConfigurationAware.js` | 46 | `return $.when.apply($, _.map(_.pairs(mapToLoad), function (loadPair) {` | _.pairs | commons | beyond | `_.map(obj, function (v, k) { return [k, v]; }) / chained .map((v,k)=>[k,v])` | yes | no - TypeError at the call | None |
| `CMN main/EventManager.js` | 61 | `eventRegistry[eventId] = _.omit(eventRegistry[eventId], function (callback) {` | _.pick/_.omit(obj, predicate) | commons | beyond | `_.reject(eventRegistry[eventId], function (callback) { return callback === callbackToRemove; })` - **changes the stored type from object back to array**; see S5 | yes | YES - pick returns {}, omit returns the whole object | None |
| `CMN main/Router.js` | 191 | `_.each(routes, function(route, key) {` | trailing thisArg | commons | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no in the ESM build (strict mode -> TypeError); YES in the AMD build (sloppy mode, `this` becomes the global) | None |
| `CMN main/ValidatorsManager.js` | 47 | `_.each(obj.afterBindValidators, function (fn) {` | trailing thisArg | commons | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no - `this` is only the `apply` receiver and every registered fn ignores it (test passes under lodash 4) | commons Vitest `ValidatorsManager > bindValidators` - executes the line, still **passes** under lodash 4 |
| `CMN util/ObjectUtil.js` | 37 | `.pairs()` | _.pairs | commons | beyond | `_.map(obj, function (v, k) { return [k, v]; }) / chained .map((v,k)=>[k,v])` | yes | no - TypeError at the call | commons Vitest `ObjectUtil > toJSONPointerMap` + `> generatePatchSet`, and `AbstractModel > patch operations` |
| `CMN util/ObjectUtil.js` | 52 | `.flatten(true)` | .flatten(true) | commons | beyond | `.flattenDeep()` | yes | YES - shallow flatten returned | commons Vitest `ObjectUtil > toJSONPointerMap` + `> generatePatchSet`, and `AbstractModel > patch operations` |
| `CMN util/ObjectUtil.js` | 205 | `.pairs()` | _.pairs | commons | beyond | `_.map(obj, function (v, k) { return [k, v]; }) / chained .map((v,k)=>[k,v])` | yes | no - TypeError at the call | commons Vitest `ObjectUtil > generatePatchSet`, `AbstractModel > patch operations` |
| `CMN util/ObjectUtil.js` | 252 | `.uniq(JSON.stringify)` | .uniq(iteratee) | commons | beyond | `.map(function (v) { return JSON.stringify(v); }).uniq().map(function (s) { return JSON.parse(s); })` | yes | YES - de-duplication silently stops | commons Vitest `ObjectUtil > generatePatchSet`, `AbstractModel > patch operations` |
| `CMN util/ObjectUtil.js` | 255 | `.pairs()` | _.pairs | commons | beyond | `_.map(obj, function (v, k) { return [k, v]; }) / chained .map((v,k)=>[k,v])` | yes | no - TypeError at the call | commons Vitest `ObjectUtil > generatePatchSet`, `AbstractModel > patch operations` |
| `CMN util/ObjectUtil.js` | 265 | `.uniq(JSON.stringify)` | .uniq(iteratee) | commons | beyond | `.map(function (v) { return JSON.stringify(v); }).uniq().map(function (s) { return JSON.parse(s); })` | yes | YES - de-duplication silently stops | commons Vitest `ObjectUtil > generatePatchSet`, `AbstractModel > patch operations` |
| `CMN util/UIUtils.js` | 383 | `.pairs()` | _.pairs | commons | beyond | `_.map(obj, function (v, k) { return [k, v]; }) / chained .map((v,k)=>[k,v])` | yes | no - TypeError at the call | None |
| `CMN util/UIUtils.js` | 611 | `return _.contains(values, item[property]);` | _.contains | commons | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `CMN util/UIUtils.js` | 631 | `return _.contains(values, item[property]);` | _.contains | commons | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `CMN util/URIUtils.js` | 120 | `return _.object(_.map(queryString.split("&"), function (pair) {` | _.object | commons | beyond | `_.reduce(pairs, function (acc, p) { acc[p[0]] = p[1]; return acc; }, {})` | yes | YES if rewritten to _.zipObject(pairs) | None |
| `MCK user/UserModel.js` | 42 | `_.any(model.getProtectedAttributes(), function (protectedAttribute) {` | _.any | commons/mock | beyond | `_.some(<same args>)` | yes | no - TypeError at the call | None |
| `USR anonymousProcess/AnonymousProcessView.js` | 181 | `_.each(["title", "completed", "failed", "tryAgain", "return"], function (key) {` | trailing thisArg | commons/user | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no in the ESM build (strict mode -> TypeError); YES in the AMD build (sloppy mode, `this` becomes the global) | None |
| `USR anonymousProcess/KBAView.js` | 108 | `var currentViewQuestion = _.findWhere(this.allQuestions, { id: questionView.getSelectedQuestionId() }),` | _.findWhere | commons/user | beyond | `_.find(coll, {..})` | yes | no - TypeError at the call | None |
| `USR anonymousProcess/KBAView.js` | 130 | `var questionView = _.findWhere(this.selectedQuestions, { id: viewId });` | _.findWhere | commons/user | beyond | `_.find(coll, {..})` | yes | no - TypeError at the call | None |
| `USR profile/AbstractUserProfileTab.js` | 154 | `.filter(function(attr) {` | trailing thisArg | commons/user | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no - `this` is unused in the predicate body | None |
| `USR profile/AbstractUserProfileTab.js` | 165 | `.map(function (attr) {` | trailing thisArg | commons/user | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no in the ESM build (strict mode -> TypeError); YES in the AMD build (sloppy mode, `this` becomes the global) | None |
| `USR profile/UserProfileKBATab.js` | 170 | `.map(function (value, key) {` | trailing thisArg | commons/user | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no in the ESM build (strict mode -> TypeError); YES in the AMD build (sloppy mode, `this` becomes the global) | None |
| `USR profile/UserProfileKBATab.js` | 175 | `.map(function (kbaPair, index) {` | trailing thisArg | commons/user | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no in the ESM build (strict mode -> TypeError); YES in the AMD build (sloppy mode, `this` becomes the global) | None |
| `USR profile/UserProfileKBATab.js` | 205 | `.object()` | _.object | commons/user | beyond | `_.reduce(pairs, function (acc, p) { acc[p[0]] = p[1]; return acc; }, {})` | yes | YES if rewritten to _.zipObject(pairs) | None |
| `USR profile/UserProfileKBATab.js` | 235 | `.map(function (value, key) {` | trailing thisArg | commons/user | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no in the ESM build (strict mode -> TypeError); YES in the AMD build (sloppy mode, `this` becomes the global) | None |
| `USR profile/UserProfileKBATab.js` | 248 | `.object()` | _.object | commons/user | beyond | `_.reduce(pairs, function (acc, p) { acc[p[0]] = p[1]; return acc; }, {})` | yes | YES if rewritten to _.zipObject(pairs) | None |
| `USR profile/UserProfileView.js` | 106 | `$.when.apply($, _.map(this.dynamicTabs, function (tab) {` | trailing thisArg | commons/user | beyond | `wrap the callback in _.bind(fn, this) (or make it an arrow)` | yes | no in the ESM build (strict mode -> TypeError); YES in the AMD build (sloppy mode, `this` becomes the global) | None |
| `AM  config/process/AMConfig.js` | 182 | `} else if (_.contains(Configuration.loggedUser.uiroles, "ui-realm-admin")) {` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  config/routes/admin/GlobalRoutes.js` | 118 | `routes[`editServer${_.capitalize(suffix)}`] = {` | _.capitalize | AM | beyond | `s.charAt(0).toUpperCase() + s.slice(1)` | yes | YES - the `directoryConfiguration` suffix becomes `Directoryconfiguration`, so the route key `editServerDirectoryConfiguration` is never registered | None |
| `AM  config/routes/admin/GlobalRoutes.js` | 131 | `routes[`editServerDefaults${_.capitalize(suffix)}`] = {` | _.capitalize | AM | beyond | `s.charAt(0).toUpperCase() + s.slice(1)` | yes | no - every suffix in this list is already all-lowercase | None |
| `AM  org/forgerock/openam/ui/admin/models/Form.js` | 35 | `const passwordProperties = _.where(schema.properties, { format: "password" });` | _.where | AM | named 3 | `_.filter(coll, {..})` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/models/Form.js` | 84 | `return _.omit(object, function (value, key) {` | _.pick/_.omit(obj, predicate) | AM | beyond | `_.pick(o, _.filter(_.keys(o), function (k) { return pred(o[k], k); }))` | yes | YES - pick returns {}, omit returns the whole object | None |
| `AM  org/forgerock/openam/ui/admin/models/Form.js` | 85 | `if (_.contains(attributes, key)) {` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/services/realm/AuthenticationService.js` | 209 | `return _.findWhere(data.result, { "_id": type });` | _.findWhere | AM | beyond | `_.find(coll, {..})` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authentication/chains/AddChainView.js` | 28 | `nameExists = _.findWhere(this.data.chainsData, { _id:name });` | _.findWhere | AM | beyond | `_.find(coll, {..})` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authentication/chains/EditLinkView.js` | 98 | `selectedOption: _.find(formData.allModules, "_id", linkConfig.module),` | 3-arg (prop, value) shorthand | AM | beyond | `_.find(formData.allModules, { _id: linkConfig.module })` | yes | YES - 3rd arg ignored, predicate degrades to truthiness of the property | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authentication/chains/EditLinkView.js` | 122 | `selectedOption: _.find(criteriaOptions, "key", linkConfig.criteria),` | 3-arg (prop, value) shorthand | AM | beyond | `_.find(criteriaOptions, { key: linkConfig.criteria })` | yes | YES - 3rd arg ignored, predicate degrades to truthiness of the property | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrArrayView.js` | 103 | `} else if (_.contains(view.IDENTITY_TYPES, type)) {` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrDayView.js` | 43 | `_.invoke(self.days, function () {` | _.invoke | AM | beyond | `_.each(self.days, function (day) { ... })` - move the body's three uses of `this` to the `day` parameter | yes (see note) | YES for the collection form | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ManageRulesView.js` | 91 | `operators = _.pluck(this.data.operators, "title"),` | _.pluck | AM | named 3 | `_.map(coll, "prop") / chained .map("prop")` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ManageRulesView.js` | 101 | `if (item && _.contains(operators, item.type)) {` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ManageRulesView.js` | 146 | `if (!this.localEntity \|\| _.contains(operators, this.localEntity.type) === false) {` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policies/EditPolicyView.js` | 131 | `(item) => _.contains(policySetModel[0].resourceTypeUuids, item.uuid));` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policies/EditPolicyView.js` | 145 | `(item) => _.contains(policySet.resourceTypeUuids, item.uuid));` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policies/EditPolicyView.js` | 147 | `self.staticAttributes = _.where(self.model.attributes.resourceAttributes, { type: "Static" });` | _.where | AM | named 3 | `_.filter(coll, {..})` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policies/EditPolicyView.js` | 148 | `self.userAttributes = _.where(self.model.attributes.resourceAttributes, { type: "User" });` | _.where | AM | named 3 | `_.filter(coll, {..})` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/authorization/policySets/EditPolicySetView.js` | 128 | `return !_.contains(self.data.entity.resourceTypeUuids, item.uuid);` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/scripts/ScriptsView.js` | 207 | `if (!_.contains(this.data.selectedUUIDs, model.id)) {` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/sessions/SessionsTable.jsx` | 42 | `const updated = _.findByValues(nextProps.data, "sessionHandle", _.pluck(this.state.checked, "sessionHandle"));` | _.pluck | AM | named 3 | `_.map(coll, "prop") / chained .map("prop")` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/admin/views/realms/sessions/SessionsView.jsx` | 62 | `const handles = _.pluck(sessions, "sessionHandle");` | _.pluck | AM | named 3 | `_.map(coll, "prop") / chained .map("prop")` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/common/components/Footer.js` | 23 | `return Configuration.loggedUser && _.contains(Configuration.loggedUser.uiroles, "ui-realm-admin");` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/common/models/JSONSchema.js` | 61 | `.pick((property) => _.has(property, "properties"))` | _.pick/_.omit(obj, predicate) | AM | beyond | `_.pick(o, _.filter(_.keys(o), function (k) { return pred(o[k], k); }))` | yes | YES - pick returns {}, omit returns the whole object | Karma `JSONSchemaTest.js > #constructor` - spec exists, runner broken (S8) |
| `AM  org/forgerock/openam/ui/common/models/JSONSchema.js` | 101 | `const collectionProperties = _.pick(raw.properties[groupKey].properties, (value) => {` | _.pick/_.omit(obj, predicate) | AM | beyond | `_.pick(o, _.filter(_.keys(o), function (k) { return pred(o[k], k); }))` | yes | YES - pick returns {}, omit returns the whole object | Karma `JSONSchemaTest.js > #constructor` - spec exists, runner broken (S8) |
| `AM  org/forgerock/openam/ui/common/models/JSONSchema.js` | 200 | `const passwordProperties = _.pick(this.raw.properties, _.matches({ format: "password" }));` | _.pick/_.omit(obj, predicate) | AM | beyond | `_.pick(this.raw.properties, _.filter(_.keys(this.raw.properties), function (k) { return _.matches({ format: "password" })(this.raw.properties[k]); }, ...))` - or keep `_.matches` and filter keys | yes | YES - pick returns {}, omit returns the whole object | None |
| `AM  org/forgerock/openam/ui/common/models/JSONSchema.js` | 208 | `return _.keys(_.pick(this.raw.properties, _.matches({ required: true })));` | _.pick/_.omit(obj, predicate) | AM | beyond | same shape as line 200, with `{ required: true }` | yes | YES - pick returns {}, omit returns the whole object | None |
| `AM  org/forgerock/openam/ui/common/models/JSONValues.js` | 45 | `.pick((property) => _.isObject(property) && !_.isArray(property))` | _.pick/_.omit(obj, predicate) | AM | beyond | `_.pick(o, _.filter(_.keys(o), function (k) { return pred(o[k], k); }))` | yes | YES - pick returns {}, omit returns the whole object | Karma `JSONValuesTest.js > #constructor` - spec exists, runner broken (S8) |
| `AM  org/forgerock/openam/ui/common/models/JSONValues.js` | 72 | `const collectionProperties = _.pick(raw[groupKey], (value) => {` | _.pick/_.omit(obj, predicate) | AM | beyond | `_.pick(o, _.filter(_.keys(o), function (k) { return pred(o[k], k); }))` | yes | YES - pick returns {}, omit returns the whole object | Karma `JSONValuesTest.js > #constructor` - spec exists, runner broken (S8) |
| `AM  org/forgerock/openam/ui/common/util/BackgridUtils.js` | 305 | `if (_.include(includeList, key)) {` | _.include | AM | beyond | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/common/util/NavigationHelper.jsm` | 52 | `Navigation.configuration.links.admin.urls.realms.urls = _.reject(` | 3-arg (prop, value) shorthand | AM | beyond | `_.reject(..., { dynamicLink: true })` | yes | YES - 3rd arg ignored, predicate degrades to truthiness of the property | None |
| `AM  org/forgerock/openam/ui/common/util/RealmHelper.js` | 134 | `if (page && _.include(subRealmSpecifiablePages, page)) {` | _.include | AM | beyond | `_.includes(<same args>)` | yes | no - TypeError at the call | Karma `RealmHelperTest.js > #getSubRealm` - spec exists, runner broken (S8) |
| `AM  org/forgerock/openam/ui/common/util/ThemeManager.js` | 108 | `theme = _.clone(theme, true);` | _.clone(x,true) | AM | beyond | `_.cloneDeep(x)` | yes | YES - deep flag ignored, shallow copy returned | Karma `ThemeManagerTest.js > updates src fields...` - spec exists, runner broken (S8) |
| `AM  org/forgerock/openam/ui/common/util/ThemeManager.js` | 121 | `return _.merge({}, parentTheme, theme, function (objectValue, sourceValue) {` | _.merge(..., customizer) | AM | beyond | `(_.mergeWith \|\| _.merge)({}, parentTheme, theme, customizer)` | yes (verified) | YES - customizer ignored, arrays merged element-wise | Karma `ThemeManagerTest.js > doesn't try to merge arrays...` - spec exists, runner broken (S8) |
| `AM  org/forgerock/openam/ui/common/util/uri/query.jsm` | 29 | `const object = _.isEmpty(paramString) ? {} : _.object(_.map(paramString.split("&"), (pair) => {` | _.object | AM | beyond | `_.reduce(pairs, function (acc, p) { acc[p[0]] = p[1]; return acc; }, {})` | yes | YES if rewritten to _.zipObject(pairs) | Karma `queryTest.js > #parseParameters` - spec exists, runner broken (S8) |
| `AM  org/forgerock/openam/ui/common/views/jsonSchema/GroupedJSONSchemaView.js` | 101 | `.invoke("render")` | _.invoke | AM | beyond | `.map(function (view) { return view.render(); })` | yes (see note) | no - the lazy wrapper returns `undefined` and the following `.each` throws | None |
| `AM  org/forgerock/openam/ui/user/login/RESTLoginView.js` | 112 | `return _.some(requirements.callbacks, "type", "PollingWaitCallback");` | 3-arg (prop, value) shorthand | AM | beyond | `_.some(requirements.callbacks, { type: "PollingWaitCallback" })` | yes | YES - 3rd arg ignored, predicate degrades to truthiness of the property | None |
| `AM  org/forgerock/openam/ui/user/login/RESTLoginView.js` | 121 | `return _.some(requirements.callbacks, "type", "ConfirmationCallback");` | 3-arg (prop, value) shorthand | AM | beyond | `_.some(requirements.callbacks, { type: "ConfirmationCallback" })` | yes | YES - 3rd arg ignored, predicate degrades to truthiness of the property | None |
| `AM  org/forgerock/openam/ui/user/login/RESTLoginView.js` | 315 | `this.userNamePasswordStage = _.contains(usernamePasswordStages, reqs.stage);` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/user/login/RESTLoginView.js` | 324 | `redirectCallback = _.object(_.map(element.output, (o) => {` | _.object | AM | beyond | `_.reduce(pairs, function (acc, p) { acc[p[0]] = p[1]; return acc; }, {})` | yes | YES if rewritten to _.zipObject(pairs) | None |
| `AM  org/forgerock/openam/ui/user/services/AuthNService.js` | 248 | `!(requirementList.length !== 0 && _.some(_.last(requirementList).callbacks, "type", "RedirectCallback"))) {` | 3-arg (prop, value) shorthand | AM | beyond | `_.some(_.last(requirementList).callbacks, { type: "RedirectCallback" })` | yes | YES - 3rd arg ignored, predicate degrades to truthiness of the property | None |
| `AM  org/forgerock/openam/ui/user/uma/models/UMAResourceSetWithPolicy.js` | 68 | `var isStarred = _.contains(this.get("labels"), starredLabelId);` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/user/uma/views/resource/LabelTreeNavigationView.js` | 59 | `if (!_.any(data.result, function (label) {` | _.any | AM | beyond | `_.some(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/user/uma/views/resource/ResourcePage.js` | 154 | `var isStarred = _.contains(self.model.get("labels"), starredLabelId);` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/user/uma/views/resource/ResourcePage.js` | 191 | `.pluck("name")` | _.pluck | AM | named 3 | `_.map(coll, "prop") / chained .map("prop")` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/user/uma/views/resource/ResourcePage.js` | 376 | `isStarred = _.contains(this.model.get("labels"), starredLabel._id);` | _.contains | AM | named 3 | `_.includes(<same args>)` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/user/uma/views/resource/ResourcePage.js` | 423 | `userLabelNames = _.pluck(userLabels, "name"),` | _.pluck | AM | named 3 | `_.map(coll, "prop") / chained .map("prop")` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/user/uma/views/resource/ResourcePage.js` | 428 | `.pluck("_id")` | _.pluck | AM | named 3 | `_.map(coll, "prop") / chained .map("prop")` | yes | no - TypeError at the call | None |
| `AM  org/forgerock/openam/ui/user/uma/views/resource/ResourcePage.js` | 433 | `.pluck("_id")` | _.pluck | AM | named 3 | `_.map(coll, "prop") / chained .map("prop")` | yes | no - TypeError at the call | None |

**Plus one non-call reference**, which no `_.contains(` grep can find:

| file | line | exact expression | API | repo | group | proposed replacement | both-major | silent | test today |
|---|---:|---|---|---|---|---|---|---|---|
| `AM  org/forgerock/openam/ui/user/UserModel.js` | 172 | `return _.spread(_.partial(_.contains, this.uiroles))(arrayify(roles));` | `_.contains` (passed as a value) | AM | named 3 | `_.spread(_.partial(_.includes, this.uiroles))` | yes | no - `_.partial(undefined, ...)` throws when called | None |

---

### 3.4 What each site became - the 8.2 outcome table

Every row of S3 that is **not** one of the three names in `tasks.md` (those were task 8.1's) was
replaced. **70 sites across 35 files** - 62 found by the first three passes, plus the 8 that only
Pass 4, Pass 5 and the widened predicate check could see (S1.6), listed at the end of the table.
Line numbers are the pre-edit ones, so this table lines up with S3 above. **`silent` marks a site
that, under lodash 4, would have run to completion and returned the wrong value** - 36 of the 70.

**Every replacement is both-major safe**, by an explicit decision recorded in S3.4.1: each one was
evaluated against the vendored 3.10.1 *and* against 4.18.1 before it was written, and all 15
replacement families came back identical (S5.1). None of `_.fromPairs`, `_.toPairs`, `_.invokeMap`,
`_.pickBy`, `_.omitBy`, `_.uniqBy`, `_.upperFirst` or `_.mergeWith` appears unguarded anywhere in
the result, because none of them exists in 3.10.1.

| file | line(s) | API / class | was | became | repo |
|---|---|---|---|---|---|
| `AM  org/forgerock/openam/ui/admin/services/realm/AuthenticationService.js` | 209 | _.findWhere | `_.findWhere(data.result, { "_id": type })` | `_.find(data.result, { "_id": type })` | AM |
| `AM  .../admin/views/realms/authentication/chains/AddChainView.js` | 28 | _.findWhere | `_.findWhere(this.data.chainsData, { _id:name })` | `_.find(this.data.chainsData, { _id:name })` | AM |
| `AM  org/forgerock/openam/ui/common/util/BackgridUtils.js` | 305 | _.include | `_.include(includeList, key)` | `_.includes(includeList, key)` | AM |
| `AM  org/forgerock/openam/ui/common/util/RealmHelper.js` | 134 | _.include | `_.include(subRealmSpecifiablePages, page)` | `_.includes(subRealmSpecifiablePages, page)` | AM |
| `AM  org/forgerock/openam/ui/common/util/uri/query.jsm` | 29 | _.object **(silent)** | `_.object(_.map(split, (pair) => [key, value]))` | `_.reduce(split, (accumulator, pair) => { accumulator[key] = value; return accumulator; }, {})` | AM |
| `AM  org/forgerock/openam/ui/user/login/RESTLoginView.js` | 324 | _.object **(silent)** | `_.object(_.map(element.output, (o) => [o.name, o.value]))` | `_.reduce(element.output, (accumulator, o) => { accumulator[o.name] = o.value; return accumulator; }, {})` | AM |
| `AM  .../user/uma/views/resource/LabelTreeNavigationView.js` | 59 | _.any | `_.any(data.result, fn)` | `_.some(data.result, fn)` | AM |
| `AM  config/routes/admin/GlobalRoutes.js` | 118, 131 | _.capitalize **(silent at 118)** | `routes[`editServer${_.capitalize(suffix)}`]` | `routes[`editServer${upperFirst(suffix)}`], with a local `upperFirst` defined above the block` | AM |
| `AM  org/forgerock/openam/ui/admin/models/Form.js` | 84 | _.omit(obj, predicate) **(silent)** | `_.omit(object, function (value, key) { … return _.isEmpty(value); })` | `_.pick(object, _.filter(_.keys(object), function (key) { … return !_.isEmpty(object[key]); }))  - predicate inverted with the pick/omit flip` | AM |
| `AM  .../authentication/chains/EditLinkView.js` | 98 | (coll,"prop",value) **(silent)** | `_.find(formData.allModules, "_id", linkConfig.module)` | `_.find(formData.allModules, { _id: linkConfig.module })` | AM |
| `AM  .../authentication/chains/EditLinkView.js` | 122 | (coll,"prop",value) **(silent)** | `_.find(criteriaOptions, "key", linkConfig.criteria)` | `_.find(criteriaOptions, { key: linkConfig.criteria })` | AM |
| `AM  .../policies/conditions/ConditionAttrDayView.js` | 43 | _.invoke(collection) **(silent)** | `_.invoke(self.days, function () { … this … })` | `_.each(self.days, function (day) { … day … })  - the two `this` reads moved onto the `day` parameter` | AM |
| `AM  org/forgerock/openam/ui/common/models/JSONSchema.js` | 61 | _.pick(pred) **(silent)** | `_(raw.properties).pick((property) => _.has(property, "properties")).keys().value()` | `_.filter(_.keys(raw.properties), (key) => _.has(raw.properties[key], "properties"))` | AM |
| `AM  org/forgerock/openam/ui/common/models/JSONSchema.js` | 101 | _.pick(pred) **(silent)** | `_.pick(raw.properties[groupKey].properties, (value) => …)` | `_.pick(groupProperties, _.filter(_.keys(groupProperties), (key) => …))` | AM |
| `AM  org/forgerock/openam/ui/common/models/JSONSchema.js` | 200 | _.pick(pred) **(silent)** | `_.keys(_.pick(this.raw.properties, _.matches({ format: "password" })))` | `_.filter(_.keys(this.raw.properties), (key) => isPasswordProperty(this.raw.properties[key]))  - `_.matches` kept, hoisted to a const` | AM |
| `AM  org/forgerock/openam/ui/common/models/JSONSchema.js` | 208 | _.pick(pred) **(silent)** | `_.keys(_.pick(this.raw.properties, _.matches({ required: true })))` | `same shape, with `isRequiredProperty`` | AM |
| `AM  org/forgerock/openam/ui/common/models/JSONValues.js` | 45 | _.pick(pred) **(silent)** | `_(raw).pick((property) => _.isObject(property) && !_.isArray(property)).keys().value()` | `_.filter(_.keys(raw), (key) => _.isObject(raw[key]) && !_.isArray(raw[key]))` | AM |
| `AM  org/forgerock/openam/ui/common/models/JSONValues.js` | 72 | _.pick(pred) **(silent)** | `_.pick(raw[groupKey], (value) => …)` | `_.pick(groupValues, _.filter(_.keys(groupValues), (key) => …))` | AM |
| `AM  org/forgerock/openam/ui/common/util/NavigationHelper.jsm` | 52 | (coll,"prop",value) **(silent)** | `_.reject(urls, "dynamicLink", true)` | `_.reject(urls, { dynamicLink: true })` | AM |
| `AM  org/forgerock/openam/ui/common/util/ThemeManager.js` | 108 | _.clone(x,true) **(silent)** | `_.clone(theme, true)` | `_.cloneDeep(theme)` | AM |
| `AM  org/forgerock/openam/ui/common/util/ThemeManager.js` | 121 | _.merge(customizer) **(silent)** | `_.merge({}, parentTheme, theme, customizer)` | `(_.mergeWith \|\| _.merge)({}, parentTheme, theme, customizer)  - a feature test, not a version test; commented in place` | AM |
| `AM  .../common/views/jsonSchema/GroupedJSONSchemaView.js` | 101 | _.invoke(collection) | `.invoke("render")` | `.map((view) => view.render())` | AM |
| `AM  org/forgerock/openam/ui/user/login/RESTLoginView.js` | 112, 121 | (coll,"prop",value) **(silent)** | `_.some(requirements.callbacks, "type", "…Callback")` | `_.some(requirements.callbacks, { type: "…Callback" })` | AM |
| `AM  org/forgerock/openam/ui/user/services/AuthNService.js` | 248 | (coll,"prop",value) **(silent)** | `_.some(…callbacks, "type", "RedirectCallback")` | `_.some(…callbacks, { type: "RedirectCallback" })` | AM |
| `CMN components/ChangesPending.js` | 49, 57, 89, 91, 101, 109, 140, 141 | _.clone(x,true) **(silent)** x8 | `_.clone(x, true)` | `_.cloneDeep(x)` | commons |
| `CMN components/ChangesPending.js` | 124 | trailing thisArg | `_.some(props, function (prop) { … this … }, this)` | `_.some(props, _.bind(function (prop) { … this … }, this))` | commons |
| `CMN components/Messages.js` | 79, 137 | _.escape **(silent, cosmetic)** x2 | `_.escape(msg.message)` | `_.escape(msg.message).replace(/`/g, "&#96;")  - restores the backtick lodash 4 stopped escaping` | commons |
| `CMN components/Navigation.js` | 300 | trailing thisArg | `_.each(navObj.urls, function (obj) { … }, this)` | `_.each(navObj.urls, _.bind(function (obj) { … }, this))` | commons |
| `CMN main/AbstractConfigurationAware.js` | 46 | _.pairs | `_.map(_.pairs(mapToLoad), function (loadPair) { … loadPair[0/1] … })` | `_.map(mapToLoad, function (moduleName, configKey) { … })  - the pair array is no longer built at all` | commons |
| `CMN main/EventManager.js` | 61 | _.omit(obj, predicate) **(silent)** | `_.omit(eventRegistry[eventId], function (callback) { … })` | `_.reject(eventRegistry[eventId], function (callback) { … })  - **deliberate behaviour fix**, see S5 note 2 and S3.4.1` | commons |
| `CMN main/Router.js` | 191 | trailing thisArg | `_.each(routes, function (route, key) { … }, this)` | `_.each(routes, _.bind(function (route, key) { … }, this))` | commons |
| `CMN main/ValidatorsManager.js` | 47 | trailing thisArg | `_.each(obj.afterBindValidators, function (fn) { … }, this)` | `_.each(obj.afterBindValidators, _.bind(function (fn) { … }, this))` | commons |
| `CMN util/ObjectUtil.js` | 37, 205, 255 | _.pairs x3 | `.pairs()` | `.map(function (value, key) { return [key, value]; })` | commons |
| `CMN util/ObjectUtil.js` | 52 | ​.flatten(true) **(silent)** | `.flatten(true)` | `.flattenDeep()` | commons |
| `CMN util/ObjectUtil.js` | 252, 265 | ​.uniq(iteratee) **(silent)** x2 | `.uniq(JSON.stringify)` | `.map(function (patch) { return JSON.stringify(patch); }).uniq().map(function (patch) { return JSON.parse(patch); })` | commons |
| `CMN util/UIUtils.js` | 383 | _.pairs (inside a Handlebars helper) | `.pairs()` | `.map(function (value, key) { return [key, value]; })` | commons |
| `CMN util/URIUtils.js` | 120 | _.object **(silent)** | `_.object(_.map(queryString.split("&"), fn))` | `_.reduce(queryString.split("&"), function (accumulator, pair) { … }, {})` | commons |
| `USR anonymousProcess/AnonymousProcessView.js` | 181 | trailing thisArg | `_.each([…], function (key) { … }, this)` | `_.each([…], _.bind(function (key) { … }, this))` | commons |
| `USR anonymousProcess/KBAView.js` | 108, 130 | _.findWhere x2 | `_.findWhere(coll, { id: … })` | `_.find(coll, { id: … })` | commons |
| `USR profile/AbstractUserProfileTab.js` | 154, 165 | trailing thisArg x2 | `.filter(fn, this) / .map(fn, this)` | `.filter(_.bind(fn, this)) / .map(_.bind(fn, this))` | commons |
| `USR profile/UserProfileKBATab.js` | 170, 175, 235 | trailing thisArg x3 | `.map(fn, this)` | `.map(_.bind(fn, this))` | commons |
| `USR profile/UserProfileKBATab.js` | 205, 248 | _.object **(silent)** x2 | `.object().value()` | `.reduce(function (accumulator, pair) { accumulator[pair[0]] = pair[1]; return accumulator; }, {})  - **the trailing `.value()` is dropped**, see S3.4.2` | commons |
| `USR profile/UserProfileView.js` | 106 | trailing thisArg | `_.map(this.dynamicTabs, function (tab) { … }, this)` | `_.map(this.dynamicTabs, _.bind(function (tab) { … }, this))` | commons |
| `MCK user/UserModel.js` | 42 | _.any | `_.any(model.getProtectedAttributes(), fn)` | `_.some(model.getProtectedAttributes(), fn)` | commons (mock) |

**The 8 sites found by Pass 4 / Pass 5 / the widened predicate check (S1.6):**

| file | line(s) | API / class | was | became | repo |
|---|---|---|---|---|---|
| `AM  .../jsonSchema/GroupedJSONSchemaView.js` | 102 | chain terminator in 4 | `.each((view) => { view.$el.appendTo(this.$el); }).value()` | `.map((view) => { view.$el.appendTo(this.$el); return view; }).value()` - `map` keeps the chain in both majors | AM |
| `AM  .../jsonSchema/GroupedJSONSchemaView.js` | 95 | _.pick/_.omit(pred) via identifier **(silent)** | `.omit(emptyProperties)` on an **Array** | `.reject(emptyProperties)` - see S3.4.2 | AM |
| `AM  .../admin/services/global/RealmsService.js` | 64 | chain terminator in 4 | `_(data.result).each((realm) => { realm.path = … }).sortBy("path").value()` | `.map((realm) => { realm.path = …; return realm; })` | AM |
| `AM  .../common/components/TabComponent.js` | 48, 49 | chain terminator in 4 x2 | `_(options.tabs).each(_.partial(has,"id")).each(_.partial(has,"title")).value()` | `_.each(options.tabs, _.partial(has, "id")); _.each(options.tabs, _.partial(has, "title"));` | AM |
| `AM  .../common/util/NavigationHelper.jsm` | 56 -> 65 | chain terminator + `.run` removed | `_(data.result).filter("active").sortBy("path").take(4).forEach(…).run()` | `const realms = _(…).filter("active").sortBy("path").take(maxRealms).value();` then `_.forEach(realms, …)` | AM |
| `AM  .../common/models/JSONSchema.js` | 238 | _.omit(obj, predicate) **(silent)** | `_.omit(this.raw.properties, predicate)` | `omitByPredicate(this.raw.properties, predicate)` - new local helper, see below | AM |
| `AM  .../common/models/JSONValues.js` | 155 | _.omit(obj, predicate) **(silent)** | `_.omit(this.raw, predicate)` | `omitByPredicate(this.raw, predicate)` | AM |

Both models gained the same local helper, because both `omit` methods are **polymorphic** - callers
pass a predicate (`JSONSchema.js:247`, `JSONEditorView.js:141`) *and* a key
(`TogglableJSONEditorView.js:38, 39`), so the fix has to keep both paths:

```js
function omitByPredicate (object, predicate) {
    if (_.isFunction(predicate)) {
        return _.pick(object, _.filter(_.keys(object), (key) => !predicate(object[key], key, object)));
    }
    return _.omit(object, predicate);
}
```

The key branch is the untouched `_.omit`; the predicate branch is the same both-major shape already
used at the six other `pick`/`omit`-with-predicate sites in this table. Duplicated in the two model
files rather than extracted, matching the local-helper precedent set by `upperFirst` in
`GlobalRoutes.js`.

Per repo: **34 sites / 19 files in `OpenAM`**, **36 sites / 16 files in `commons`**
(24 in `ui/commons`, 11 in `ui/user`, 1 in `ui/mock`).

#### 3.4.1 The four decisions this task did not make on its own

Each of these was a choice between defensible alternatives rather than something derivable from the
code, and each was put to the change owner before anything was written.

1. **The silent sites: both-major, not idiomatic lodash 4.** `_.object` -> `_.fromPairs`,
   `_.pairs` -> `_.toPairs` and `_.invoke` -> `_.invokeMap` are the idiomatic lodash 4 spellings,
   and **all three are absent from 3.10.1** (re-measured, S5). Writing them would throw in the
   browser from this commit until 8.3 lands - and, for the commons sites, **permanently**, because
   `openidm-ui` and `openig-ui` load 3.10.1 from `commons.ui:*:zip:www` and 8.3 does not touch them
   (S5). Decision: **both-major expressions everywhere**, consistent with all 29 of task 8.1's
   sites. The naive `_.zipObject(pairs)` rewrite was rejected for the same reason it is dangerous:
   it is green and wrong (S4.1).
2. **`CMN main/EventManager.js:61` - fix, not preserve.** Measured on 3.10.1,
   `_.omit(array, predicate)` returns an **object** (`{"0":cbA,"2":cbC}`), not an array, so the
   listener list loses `.push` and `unregisterListener` is **already latently broken today**.
   `_.reject` is identical under both majors and returns an array. Decision: **take the fix**. This
   is the one line in 8.2 that deliberately changes behaviour under lodash 3 as well, and it should
   be called out in review rather than read as a mechanical rename.
3. **`AM .../ThemeManager.js:121` - ship the feature test.** `(_.mergeWith || _.merge)` is one
   token, verified identical under both majors, and survives 8.3 with no further edit; the
   alternative was a hand-rolled recursive merge. Decision: **the feature test**, with a comment
   saying why.
4. **`commons/ui/mock` is in scope.** S10 of the 8.1 pass explicitly refused to decide this. The
   module is outside the three trees the task brief named but sits in the same reactor and breaks
   the same way. Decision: **include it** - one both-major-safe line (`_.any` -> `_.some`).

#### 3.4.2 Four rewrites that are not one-for-one, and why

* **`USR profile/UserProfileKBATab.js:205, 248` lose their trailing `.value()`.** The chain was
  `_(x).map(…).object().value()`. `reduce` is a chain **terminator**: in an implicitly-chained
  `_(x)` sequence it returns the unwrapped value, so a following `.value()` throws
  `.value is not a function`. Measured, and it is **the same in both majors** - so the `.value()`
  had to go with the `.object()`, not survive it. `_.chain(x)` sequences (e.g.
  `AbstractUserProfileTab.js`) are unaffected and keep their `.value()`.
* **`AM config/routes/admin/GlobalRoutes.js` gains a local `upperFirst`.** lodash 4's `capitalize`
  lower-cases the tail, so it is not a drop-in for lodash 3's; `_.upperFirst` does not exist in
  3.10.1. A two-line local helper is both-major by construction. Verified against all eight
  suffixes in both lists: `upperFirst` reproduces lodash 3's `capitalize` exactly, including
  `directoryConfiguration` -> `DirectoryConfiguration`, which is the whole point (S4.2).
* **`AM .../GroupedJSONSchemaView.js:95` changes its result type, deliberately.**
  `orderedSchemaValuePairs` is an **Array**, and `_.omit(array, predicate)` returns an **Object**
  keyed by index under lodash 3 - the same defect as `EventManager.js:61` (S3.4.1 decision 2), here
  masked because the next link is `_(obj).map(…)`, which iterates values either way. `.reject()`
  returns an Array under both majors. Measured equal on the values; the container type changes from
  `{0:…,2:…}` to `[…]`, which nothing downstream distinguishes.
* **`CMN util/ObjectUtil.js:252, 265` drop a `value: undefined` key.** `_.uniq(arr, JSON.stringify)`
  became `.map(JSON.stringify) -> .uniq() -> .map(JSON.parse)`, and a round-trip through JSON
  discards an explicitly-`undefined` property that the original preserved on the returned object.
  Measured. Harmless here - patch sets are serialised to JSON downstream anyway - but it is not
  strictly one-for-one and is recorded rather than glossed. (The callbacks are wrapped in
  `function (patch) { … }` rather than passed bare: `_.map` would otherwise hand `JSON.stringify`
  the index as its `replacer` argument.)

---

## 4. Silent-failure sites, named individually

A site is listed here when the code under lodash 4 - either as written, or after the rewrite a
reader would reach for first - runs to completion and produces a wrong value. These are the rows
8.1 must not treat as mechanical.

### 4.1 The two the brief names, both confirmed

**`_.object(pairs)` -> `_.zipObject(pairs)` is green and wrong.** `_.object` is an alias of
`_.zipObject` in lodash 3, so the obvious rewrite is to spell out the alias. Under lodash 4
`_.zipObject` takes `(keys, values)`, so `_.zipObject([["a",1]])` returns `{"a,1": undefined}` -
no error, an object of the right shape, entirely wrong contents. The lodash 4 name for the pairs
form is `_.fromPairs`, which **does not exist in 3.10.1**.

Three sites, and the arguments put all three squarely in the dangerous case (each passes a single
array of two-element arrays, never a keys/values pair):

* `AM  org/forgerock/openam/ui/common/util/uri/query.jsm:29` - query-string parsing. Every
  `?realm=/x` on every page goes through it.
* `AM  org/forgerock/openam/ui/user/login/RESTLoginView.js:324` - the `redirectCallback`
  name/value map in the login flow.
* `CMN util/URIUtils.js:120` - `parseQueryString`, the commons original that `RealmHelper`,
  `ThemeManager`, `AMConfig`, `Router.convertQueryParametersToJSON` and both openidm-ui consoles
  all call.

Two more, in a chain: `USR profile/UserProfileKBATab.js:205` and `:248` end `.map(...).object()`.
Under lodash 4 `.object` is simply absent, so those two fail loudly instead - unless the rewriter
reaches for `.zipObject()`, at which point they join the list above.

**`_.invoke(collection, method)` is a collection operation in 3 and a path-invocation on a single
object in 4.** Two sites, and only one is in the dangerous case:

* `AM  .../conditions/ConditionAttrDayView.js:43` - **dangerous.** `_.invoke(self.days, function () {...})`
  with `self.days = ["Monday", ... "Sunday"]` and the callback reading `this` as the day name.
  lodash 3 calls the function once per element with `this` bound to it; lodash 4 treats the
  function as a *path*, calls nothing, returns `undefined`. `weekdays` stays `[]`, `getWeekDays()`
  returns an empty array and the day-of-week condition editor renders an empty dropdown with no
  error anywhere. `_.invokeMap` is the lodash 4 name and **does not exist in 3.10.1**; the
  both-major replacement is `_.each` with the element as a parameter.
* `AM  .../jsonSchema/GroupedJSONSchemaView.js:101` - **not** dangerous. `.invoke("render")` inside
  a lazy wrapper returns `undefined` in 4 and the following `.each(...)` throws immediately.

### 4.2 Silent sites the brief does not name - the ones with the same property

* **`_.clone(x, true)` - 9 sites.** lodash 4 ignores the second argument; the call returns a
  *shallow* copy and never says so. `CMN components/ChangesPending.js` (8 sites) is the whole
  point of the module: it clones `watchedObj` to compare it against later edits. A shallow clone
  makes the clone alias the original's nested objects, so `compareObjects` compares a value with
  itself and "unsaved changes" silently stops being detected. `AM .../ThemeManager.js:108` shallow-
  clones the theme and then mutates `theme.settings.logo.src` **in place on the shared theme
  object** - the first realm to load rewrites the logo URL for every realm after it.
* **`_.pick`/`_.omit(obj, predicate)` - 8 sites.** lodash 4 treats a function argument as a path.
  `_.pick` returns `{}`, `_.omit` returns the whole object. Both are valid objects. Consequences:
  `AM .../models/JSONSchema.js:61,101` and `.../JSONValues.js:45,72` decide which schema properties
  are "collections" - with `{}` every grouped console form silently loses its grouping;
  `JSONSchema.js:200,208` return the password and required key lists - with `{}` password fields
  stop being masked and required fields stop being enforced; `AM .../models/Form.js:84` and
  `CMN main/EventManager.js:61` are `_.omit`, so they keep everything they were told to drop -
  `EventManager.unregisterListener` silently stops unregistering.
* **`(coll, "prop", value)` shorthand - 6 sites.** lodash 4 ignores the third argument and the
  predicate degrades to "the property is truthy". `_.some(requirements.callbacks, "type", "PollingWaitCallback")`
  becomes "any callback has a truthy `type`" - true for every callback there is, so
  `RESTLoginView.js:112,121` and `AuthNService.js:248` take the polling / confirmation / redirect
  branch on every login. `EditLinkView.js:98,122` return the *first* module rather than the matching
  one. `NavigationHelper.jsm:52` rejects every realm link instead of the dynamic ones.
* **`_.capitalize("directoryConfiguration")` - `AM config/routes/admin/GlobalRoutes.js:118`.**
  lodash 4 lower-cases the tail: `"DirectoryConfiguration"` becomes `"Directoryconfiguration"`.
  The route registers under `editServerDirectoryconfiguration`, nothing links to that key, and the
  Directory Configuration tab of the server editor 404s inside the router. The sibling at line 131
  has no camelCase suffix in its list and is safe - a good illustration of why the argument, not
  the API, decides.
* **`_.merge(..., customizer)` - `AM .../util/ThemeManager.js:121`.** lodash 4 dropped customizer
  support from `_.merge` (it is `_.mergeWith` there). The customizer exists precisely to stop
  arrays being merged element-wise. Verified: `_.merge({}, {x:{arr:[1,2,3]}}, {x:{arr:[9]}}, cust)`
  gives `{x:{arr:[9]}}` under 3 and `{x:{arr:[9,2,3]}}` under 4. A theme that overrides a
  stylesheet list keeps the parent's trailing entries. There is a Karma spec asserting exactly this
  (`doesn't try to merge arrays in the selected theme with the default theme`) and it cannot run
  today (S8.2).
* **`.flatten(true)` - `CMN util/ObjectUtil.js:52`.** lodash 4's `flatten` is shallow-only and
  ignores the flag. `toJSONPointerMap` returns nested arrays instead of a flat pointer list, so
  `generatePatchSet` emits malformed PATCH bodies.
* **`.uniq(JSON.stringify)` - `CMN util/ObjectUtil.js:252, 265`.** lodash 4 ignores the iteratee
  (`uniqBy` there). De-duplication of patch operations silently stops; the comment above the call
  says in as many words why it is there.
* **`_.escape` - `CMN components/Messages.js:79, 137`.** lodash 4 no longer escapes `` ` ``.
  Cosmetic in HTML text content, listed for completeness rather than severity.
* **trailing `thisArg` - 11 sites** - is *not* generally silent, and that is worth stating
  precisely because it depends on which build is running. In the AMD build the callback bodies are
  sloppy-mode, so `this` becomes the global object and `this.data`/`this.$el` read as `undefined`
  before failing somewhere else. In the **emitted ES module build** every module is strict, so
  `this` is `undefined` and the first property read throws at the call. Two of the eleven are
  harmless either way and should still be rewritten: `CMN main/ValidatorsManager.js:47` (the
  `this` is only `apply`'s receiver and every registered function ignores it - confirmed, that
  test still passes under lodash 4) and `USR profile/AbstractUserProfileTab.js:154` (the predicate
  body never mentions `this`).

---

## 5. Both-major safety

`commons/ui/pom.xml` ships `org.openidentityplatform.commons.ui.libs:lodash:3.10.1` in the
`commons.ui:*:zip:www` artifacts, and that is what the two downstream products actually load:

* `OpenIG/openig-ui/src/main/js/main.js:46` - `lodash: "libs/lodash-3.10.1-min"`, with
  `"underscore": "lodash"` in `require.config.map` (line 25). Its `package.json` says
  `"lodash": ">=4.17.23"` - that is the build toolchain, not the runtime.
* `OpenIDM/openidm-ui/openidm-ui-{admin,enduser}/src/main/js/main.js` - both
  `lodash: "libs/lodash-3.10.1-min"` with the same `underscore` remap.
  `OpenIDM/openidm-ui/pom.xml` additionally declares the 2.4.1 artifact.

Both declare `commons.ui:commons:zip:www` as a dependency, so **every line 8.1 changes in
`commons/ui/{commons,user}` executes on lodash 3.10.1 in two products this change does not touch.**

**Verified: no proposed replacement in the table is both-major unsafe.** All 90 rows are `yes` in
the `both-major` column, because the replacements were chosen to avoid the lodash-4-only names
entirely. The five names a naive rewrite would reach for **do not exist in 3.10.1** and were
confirmed absent by evaluation:

| lodash 4 name | in 3.10.1? | both-major replacement used instead |
|---|---|---|
| `_.fromPairs(pairs)` | **no** | `_.reduce(pairs, function (a, p) { a[p[0]] = p[1]; return a; }, {})`, or `_.zipObject(_.map(pairs, p => p[0]), _.map(pairs, p => p[1]))` |
| `_.toPairs(obj)` | **no** | `_.map(obj, function (v, k) { return [k, v]; })` |
| `_.pickBy` / `_.omitBy` | **no** | `_.pick(o, _.filter(_.keys(o), k => pred(o[k], k)))` |
| `_.invokeMap(coll, m)` | **no** | `_.each` / `.map(v => v.m())` |
| `_.uniqBy(a, it)` | **no** | `.map(JSON.stringify-in-a-lambda).uniq().map(JSON.parse-in-a-lambda)` |
| `_.upperFirst(s)` | **no** | `s.charAt(0).toUpperCase() + s.slice(1)` |
| `_.mergeWith(...)` | **no** | `(_.mergeWith \|\| _.merge)(...)` - verified identical under both |

### 5.1 The 8.2 differential run - every replacement family, measured

Re-run in task 8.2 **before** each replacement was written, against the two libraries loaded from
disk. `SAME` means the two majors produced identical JSON for the replacement expression.

| replacement family | lodash 3.10.1 | lodash 4.18.1 | verdict |
|---|---|---|---|
| `_.find(coll, {k:v})` | `{_id:"b",…}` | `{_id:"b",…}` | SAME |
| `_.some(coll, {k:v})` | `true` | `true` | SAME |
| `_.reject(coll, {k:v})` | `[{n:2}]` | `[{n:2}]` | SAME |
| `_.filter(_.keys(o), (k) => matcher(o[k]))` | `["a"]` | `["a"]` | SAME - and equal to lodash 3's `_.keys(_.pick(o, matcher))` |
| `_.pick(o, arrayOfKeys)` **with a dotted key present** | keeps `"dotted.key"` | keeps `"dotted.key"` | SAME - lodash 4 resolves an own property before it tries a path |
| `.flatten(true)` -> `.flattenDeep()` | `[1,2,3,4]` | `[1,2,3,4]` | SAME |
| plain `.flatten()` (untouched, S6.3-style) | `[1,2,[3,[4]]]` | `[1,2,[3,[4]]]` | SAME - shallow in both, correctly **not** a site |
| `.map(stringify).uniq().map(parse)` | `[{op:"a"},{op:"b"}]` | `[{op:"a"},{op:"b"}]` | SAME - and equal to lodash 3's `.uniq(JSON.stringify)` |
| `.map((v,k) => [k,v])` | `[["x",1],["y",2]]` | `[["x",1],["y",2]]` | SAME - and equal to lodash 3's `.pairs()` |
| `_.reduce(pairs, …, {})` | `{a:"1",b:"2"}` | `{a:"1",b:"2"}` | SAME - and equal to lodash 3's `_.object(…)` |
| `_.cloneDeep(x)` | deep copy | deep copy | SAME - and equal to lodash 3's `_.clone(x, true)` |
| `_.escape(s).replace(/\`/g,"&#96;")` | unchanged | backtick restored | SAME - and byte-equal to lodash 3's bare `_.escape` |
| `(_.mergeWith \|\| _.merge)(…, customizer)` | picks `merge` -> `{x:{arr:[9]},k:1}` | picks `mergeWith` -> `{x:{arr:[9]},k:1}` | SAME (bare `_.merge` under 4 gives `{arr:[9,2,3]}`) |
| `upperFirst(s)` | - | - | reproduces lodash 3 `_.capitalize` on all 8 suffixes |
| `_.reject(arr, pred)` (EventManager) | `Array`, len 2 | `Array`, len 2 | SAME across majors; **deliberately different from today's `_.omit`**, see S3.4.1 |

`_(x).map(…).reduce(fn, {})` returns the **unwrapped** value in both majors - the finding behind
S3.4.2.

Three replacements deserve a note rather than a flat "yes":

1. **`(_.mergeWith || _.merge)` (`ThemeManager.js:121`)** works because the two functions have the
   same signature in their respective majors. Verified: both give `{x:{arr:[9]},k:1}`. It is a
   feature test, not a version test, so it also survives 8.3 flipping the alias. If 8.1 would
   rather not ship a feature test in product code, the alternative is a hand-rolled recursive
   merge - but plain `_.merge` without a customizer is **not** an option; it changes behaviour
   under both majors.
2. **`CMN main/EventManager.js:61`** is the one row where "identical to lodash 3" and "correct" are
   different requests. `_.omit(anArray, predicate)` in lodash 3 returns an **object** - it converts
   the listener array into `{0: cb1, 2: cb3}` and every later `.push` on it fails. The proposed
   `_.reject(...)` is identical under both majors but is **not** identical to today's lodash 3
   output: it fixes a latent bug. 8.1 should make that a deliberate decision rather than a
   side effect.
3. **`_.escape(s).replace(/`/g, "&#96;")`** is a no-op under lodash 3 (which already produced
   `&#96;`) and restores the 3 behaviour under 4. Verified byte-identical on
   ``a`b<c>&'d"``.

**Downstream verdict: no, nothing in the proposed commons rewrite breaks openidm-ui or openig-ui** -
every commons replacement was evaluated against the same 3.10.1 file those products load. For
context, `openidm-ui`'s own sources carry 60 removed-API calls of their own (21 `_.contains`,
21 `_.findWhere`, 11 `_.pluck`, 3 `_.where`, 2 `_.sortByAll`, 1 `_.object`, 1 `_.pairs`) and
`openig-ui` carries 1 (`_.sortByOrder`); none of that is group 8's to fix, and none of it is
touched by a both-major-safe commons rewrite.

---

## 6. Adjacent hazards 8.1/8.3 will hit that are not in the table

### 6.1 Backbone and Backgrid are `underscore` consumers, and `underscore` is aliased to lodash

`vite.config.js:3041` maps `underscore` to the vendored lodash 3.10.1 file. The installed
`backbone@1.1.2` and `backgrid@0.3.5` both `require("underscore")`, and both call removed APIs:

| package | removed-API calls in its own source |
|---|---|
| `backbone@1.1.2` | `_.any` x1 |
| `backgrid@0.3.5` | `_.contains` x11, `_.pluck` x8, `_.all` x4, `_.any` x3, `_.where` x4, `_.object` x2, `_.pairs` x3, `_.findWhere` x2, `_.indexBy` x2, `_.select`, `_.detect`, `_.collect`, `_.compose`, `_.foldl`, `_.foldr`, `_.inject`, `_.include`, `_.methods`, `_.unique` |

`Backbone.Collection.prototype.pluck` is `_.invoke(this.models, "get", attr)` - under lodash 4 that
is a path-invocation and returns `undefined`. Five AM source lines call Backbone collection
methods, not lodash, and are therefore **not** in the table, but break for this reason:

* `AM .../uma/views/resource/ResourcePage.js:219` - `this.model.get("scopes").pluck("name")`
* `AM .../uma/views/share/CommonShare.js:165, 241` - `...get("scopes").pluck("name")`
* `AM .../uma/views/share/CommonShare.js:236` - `...get("permissions").findWhere({subject: value})`
* `AM .../uma/views/request/EditRequest.js:112` - `self.data.requests.findWhere({_id: id})`

**This is 8.3's problem, and it has a cheap answer this pass measured:** the real
`underscore@1.13.7` is already installed in `openam-ui-ria/node_modules`, and it still exports 19
of the 31 removed names - `all any collect compose contains detect findWhere foldl foldr include
indexBy inject methods object pairs pluck select unique where`. Pointing the `underscore` alias at
the actual underscore package (or leaving it on lodash 3.10.1) while `lodash` moves to 4 keeps
Backbone and Backgrid working without touching either vendored library.

### 6.2 Nothing under `src/main/js/libs/` calls a removed API

Checked directly, both as `_.<name>(` and as any `.<name>(` property call, over all eleven files in
`openam-ui-ria/src/main/js/libs/`: **zero hits**. The AST scan of that directory finds 0 lodash
calls at all. `jsoneditor-0.7.23-custom.js`, `form2js`, `js2form`, `bootstrap-tabdrop`,
`popover-clickaway`, `backgrid-paginator` and the rest use jQuery, not lodash. The vendored
`lodash-3.10.1-min.js` is the library itself. So the answer to "does a vendored file call a removed
API" is **no** - the vendored-consumer problem lives one level out, in `node_modules`
(S6.1), where the owner is 8.3's alias decision rather than a file in this repo.

### 6.3 `_.reduce(values, _.merge, {})` is fine

`AM .../jsonSchema/GroupedJSONSchemaView.js:120` passes `_.merge` straight to `_.reduce`, so it is
invoked as `_.merge(acc, value, index, collection)`. Checked in both majors: same result. Not a
site.

---

## 7. The commons propagation chain

A source edit in `commons/ui/commons/src/main/js` is invisible to `npx vite build` in
`openam-ui-ria` until the packed tarball is rebuilt **and reinstalled**. AM's build consumes
`node_modules/@openidentityplatform/ui-{commons,user}/{amd,esm,www}` (`vite.config.js` lines
419-422, 641-644, 1855-1856), never the sibling checkout.

**A full `mvn install` in `commons/ui` is NOT required.** The packed tarball installs into AM by
path. Measured sequence, all four steps run in this pass:

```bash
# 1. regenerate the emitted amd/ esm/ www/ trees from src/main/js       (~2 s)
npm --prefix <FR>/commons/ui/commons run build:npm
npm --prefix <FR>/commons/ui/user    run build:npm      # only if ui/user was edited

# 2. pack.  The working directory MUST be target/npm - from the module root
#    npm packs src/, target/ and pom.xml under the same tarball name and nothing warns.
( cd <FR>/commons/ui/commons/target/npm && npm pack --pack-destination <FR>/commons/ui/commons/target )
( cd <FR>/commons/ui/user/target/npm    && npm pack --pack-destination <FR>/commons/ui/user/target )

# 3. install BOTH tarballs into AM in ONE command                        (~2 s)
( cd <FR>/OpenAM/openam-ui/openam-ui-ria && \
  npm install <FR>/commons/ui/commons/target/openidentityplatform-ui-commons-3.2.0-SNAPSHOT.tgz \
              <FR>/commons/ui/user/target/openidentityplatform-ui-user-3.2.0-SNAPSHOT.tgz \
              --no-save --legacy-peer-deps --prefer-offline --no-audit --no-fund )

# 4. build                                                               (~14 s)
( cd <FR>/OpenAM/openam-ui/openam-ui-ria && npx vite build )
```

Three things this pass learned the hard way and that are load-bearing:

* **Step 3 must name both tarballs.** Installing only `ui-commons.tgz` **deleted**
  `node_modules/@openidentityplatform/ui-user` - observed, not theorised. npm reconciles the
  `@openidentityplatform` scope against what the single command names. The pom's
  `npm-install-commons` execution passes both for exactly this reason.
* **`--prefer-offline --no-audit --no-fund` turns 10 minutes into 2 seconds.** The same command
  without them took 10m07s on a warm tree, almost all of it registry metadata and the audit.
* `--legacy-peer-deps` is not optional - both packages declare their runtime libraries as
  `peerDependencies`, and without the flag npm resolves ~50 unpinned packages from the registry
  and prunes on every run. This is documented at length in `openam-ui-ria/pom.xml`.

`mvn install -f commons/ui/pom.xml` is only needed to refresh `~/.m2` for a **Maven** build of AM
(the pom's `copy-commons-npm-tarballs` resolves `commons.ui:{commons,user}:tgz:npm:3.2.0-SNAPSHOT`
from `~/.m2` only - no repository publishes them), and to run the QUnit half of the commons suite
through `ui/mock`. For an edit-build-look loop, steps 1-4 are enough.

Evidence the chain closed: after step 3 the installed
`@openidentityplatform/ui-commons/{amd,esm}/.../util/UIUtils.js` carries the two
`_.contains(values, item[property])` lines from the checkout, and after step 4
`target/compiled/assets/main-*.js` contains `toJSONPointerMap` from `ObjectUtil.js`. The build
completed in 13.72 s with exit code 0.

**Do not run `mvn clean` inside `openam-ui`, and do not run `mvn ... -am` from the OpenAM root.**
(`openam-ui-ria/pom.xml` records that task 4.8 removed the `clean-external` goal that made this
destructive; the prohibition is kept here because the `~/.m2`-only tgz artifacts still are.)

---

## 8. Which tests exercise the edited files, and how to run them

### 8.1 commons Vitest - the only suite that runs today and has teeth

```bash
npm --prefix <FR>/commons/ui/commons run test:esm     # vitest run; 9 files, 32 tests
npm --prefix <FR>/commons/ui/user    run test:esm     # 1 file, 1 test (import smoke only)
npm --prefix <FR>/commons/ui/commons run verify:esm   # bare-Node import check
npm --prefix <FR>/commons/ui/user    run verify:esm
```

It runs against the **emitted** `target/npm/esm` tree, so step 1 of S7 must precede it.
Run in this pass: **32 passed**, in 3.3 s, resolving `commons/ui/commons/node_modules/lodash`,
which is **3.10.1**.

The suite was then re-run with lodash **4.18.1** aliased in (a scratch config, since removed, that
imported the project's `vitest.config.mjs` and prepended a `lodash` alias to
`openam-ui-ria/node_modules/lodash/lodash.js`). Result: **3 of 32 failed**, all
`TypeError: default.chain(...).pairs is not a function`:

* `ObjectUtil > toJSONPointerMap` - `CMN util/ObjectUtil.js:37`
* `ObjectUtil > generatePatchSet` - `CMN util/ObjectUtil.js:37, 205, 255`
* `AbstractModel > patch operations` - reaches the same line through `obj.sync`

That is the entire executable safety net for 91 sites: **7 of them**, and all 7 in one file.

The proposed replacements were then proved by patching the **generated** file
`commons/ui/commons/target/npm/esm/.../ObjectUtil.js` (never the tracked source) with
`.map((v,k)=>[k,v])`, `.flattenDeep()` and the stringify/uniq/parse form, and re-running under
lodash 4: **32 passed**. The file was restored from a `.bak` immediately afterwards.

Second-order finding from that run: with `.pairs()` fixed, the suite passes under lodash 4 **even
though `CMN main/ValidatorsManager.js:47` still has its `thisArg`**. That site is executed by
`ValidatorsManager > bindValidators` and the test does not notice - it asserts on the arguments the
callback receives, not on its `this`. So the suite proves the `thisArg` there is harmless; it does
not police the other ten.

### 8.2 commons QUnit - the AMD mirror, Maven-driven

The same ten suites exist as `commons/ui/{commons,user}/src/test/qunit/*.js` and run through
`commons/ui/mock` (Grunt task `qunit`, file list in `mock/src/test/qunit/tests/main.js`). They need
the Maven-staged libs, so the route is `mvn install -f <FR>/commons/ui/pom.xml`, or `npx grunt build`
in `commons/ui/mock` once `target/` is staged. **`user/AnonymousProcessView` is commented out of
that list**, so `commons/ui/user` has no behavioural test on either side - and seven of the eleven
`thisArg` sites live there.

### 8.3 AM Karma - 20 specs exist; the runner does not work

`npm test` in `openam-ui-ria` is a stub that prints a message and exits 0. `npm run test:unit`
(`vitest run`) finds **no test files** - the specs are `*Test.js`, not `*.test.mjs`.
`npm run test:karma` (`grunt karma:build`) was run in this pass and **fails**:

```
Uncaught Error: Script error for "store/actions/types", needed by:
  target/test-classes/store/actions/creatorsTest.js, ...
Warning: Task "karma:build" failed.
```

The composed Grunt tree it loads from is gone since the Vite migration. So for the AM half of this
inventory, **every `test today` cell that names a Karma spec means "a spec exists that would
execute this line, and it cannot be run today"**. Those specs, and the sites they would cover:

| spec | covers |
|---|---|
| `queryTest.js > #parseParameters` | `query.jsm:29` (`_.object`) |
| `ThemeManagerTest.js` | `ThemeManager.js:108` (`_.clone(x,true)`), `:121` (merge customizer) |
| `JSONSchemaTest.js > #constructor` | `JSONSchema.js:61, 101` (`_.pick(pred)`) |
| `JSONValuesTest.js > #constructor` | `JSONValues.js:45, 72` (`_.pick(pred)`) |
| `RealmHelperTest.js > #getSubRealm` | `RealmHelper.js:134` (`_.include`) |

`JSONSchema.js:200` (`getPasswordKeys`) and `:208` (`getRequiredPropertyKeys`) have **no** spec,
despite being the two sites where a silent `{}` disables password masking and required-field
enforcement.

### 8.4 Playwright

`OpenAM/e2e/xui/*.spec.mjs`, run with `npm --prefix OpenAM/e2e run test:xui`. **Not executed in
this pass** - they need a deployed AM, which is task 8.3's job. No `test today` cell claims a
Playwright spec, deliberately: naming one without running it would be a guess. For 8.3's planning,
the specs that clearly drive a screen containing a site in this table are `xui-login`
(`AMConfig.js:182`, `Footer.js:23`, `RESTLoginView.js:112,121,315,324`, commons `Navigation.js:180`,
`RoleFilter.js:37`, `Router.js:191`, `URIUtils.js:120`, `GlobalRoutes.js:118`), `xui-profile`
(commons `ChangesPending.js`, `UserProfileView.js:106`, `AbstractUserProfileTab.js`),
`xui-realms` (`NavigationHelper.jsm:52`), `xui-theming` (`ThemeManager.js:108,121`),
`xui-auth-chains` (`AddChainView.js:28`, `EditLinkView.js:98,122`) and `xui-auth-modules`
(`AuthenticationService.js:209`). Nothing exercises UMA, policies, policy sets, scripts, sessions
or the KBA views at all.

### 8.5 Coverage, counted

**8 of 91 sites are executed by a test that can be run today** (the 7 `ObjectUtil.js` sites plus
`ValidatorsManager.js:47`), and only the 7 actually fail when lodash 4 is substituted. A further
**8** have a Karma spec that exists but cannot run. The remaining **75 have nothing**.

---

## 9. The two peer ranges

`commons/ui/commons/package.json` and `commons/ui/user/package.json` both declare
`"lodash": ">=3.10.1"` and both carry a `//peerDependencies-lodash` note. **Neither was edited -
that is task 8.3.**

The commons note says the range is deliberately not a caret because openam-ui-ria "ships lodash
3.10.1 at runtime ... while its own package.json devDependency pins 4.18.1 for the build
toolchain"; that lodash is the only one of the 18 peers present in AM's npm tree at all, so
`^3.10.1` made the tarball ERESOLVE-impossible to install into its only phase-1 consumer; and
`>=3.10.1` rather than `^3.10.1 || ^4.0.0` because *"the source is written against lodash 3
semantics and 8.1 has not yet replaced the 25 call sites of APIs lodash 4 removed (`_.pluck`,
`_.contains`, `_.where`)"*. The ui/user note restates the same reasoning and adds that the two
packages must state the same range "or the conflict simply moves".

**The claim, restated:** after 8.1-8.3 the source will no longer use APIs lodash 4 removed, so the
range can widen to assert lodash 4 compatibility.

**Does the claim survive this inventory? Half of it.**

* The *shape* of the claim survives. Every one of the 91 sites has a replacement that is
  identical under both majors, so a widened range can be honest without stranding openidm-ui or
  openig-ui - see S5.
* The *number* does not. It is 91 sites, not 25 (S2.4). The two names in the parenthetical are
  also incomplete in a way that matters for scoping 8.1: `_.contains`, `_.pluck` and `_.where` are
  46% of the removed-API sites and 31% of the whole job, and **none of the eight silent-failure
  classes in S4 is one of them**.
* The wording "APIs lodash 4 removed" is too narrow for what has to happen. 44 of the 91 sites use
  an API lodash 4 still exports under the same name. A range widened after fixing only removals
  would assert a compatibility the source does not have.
* One thing the notes get exactly right and 8.3 should keep: `>=3.10.1` is not merely a
  compatibility statement, it is what makes the tarball installable into a tree holding lodash
  4.18.1. Whatever 8.3 widens it to must still satisfy `4.18.1` **and** `3.10.1`, because the
  `commons.ui:*:zip:www` channel that feeds openidm-ui and openig-ui still ships 3.10.1
  (`commons/ui/pom.xml:85-90`) and neither product's `main.js` has moved off
  `libs/lodash-3.10.1-min`. `^3.10.1 || ^4.0.0` says that; a bare `^4` does not.

---

## 10. Open / not determined

*(Written during the 8.1 pass. The `commons/ui/mock` entry was closed by 8.2; the two test-runner
entries remain open and are restated as boundary items 6 and 7 in S12.)*

* **Whether the Playwright suite actually exercises any of these sites.** Not run - it needs a
  deployed AM (8.3). S8.4 lists which specs drive which screens; it does not claim coverage.
* **Whether the AM Karma specs pass once a runner exists.** `grunt karma:build` fails on the
  composed tree before reaching any assertion, so the five specs in S8.3 are "would execute", not
  "does execute". Restoring them is D12 / group 9, not group 8.
* ~~**`commons/ui/mock`** … whether 8.1 owns it is a scoping question this pass does not decide.~~
  **Decided in 8.2: in scope.** `MCK user/UserModel.js:42` is now `_.some`. See S3.4.1 item 4.

---

## 11. Reproducing this file

Everything above is derived from five throwaway Node/Python scripts run against the two checkouts
and the two lodash builds. They were deleted after the run; each is described precisely enough in
S1 to rewrite in a few minutes. Two temporary files touched a working tree and were both undone:

| file | what | state now |
|---|---|---|
| `commons/ui/commons/vitest.lodash4.probe.mjs` | scratch vitest config aliasing lodash 4 in | deleted |
| `commons/ui/commons/target/npm/esm/.../ObjectUtil.js` | patched, then restored from `.bak` | restored; `target/` is regenerated by `build:npm` anyway |

`git status` after the **8.1** pass: `commons` clean; `OpenAM` shows only untracked `NOTES-*.md`
files that predate it.

**Task 8.2 then modified source.** `git status` after 8.2: 17 modified files in `OpenAM` plus this
file (now tracked), and 16 modified files in `commons`. The 8.2 measurement scripts - the two
`@babel/parser` scans and the four differential probes - were written to the session scratchpad,
never into either working tree, and are described precisely enough in S1.5 and S5.1 to rewrite.
`package.json`, `package-lock.json` and `vite.config.js` were **not** touched in either repo.

Side effects that were **not** undone, because they are the build's own normal output:
`commons/ui/{commons,user}/target/npm` and the two `.tgz` were regenerated,
`openam-ui-ria/node_modules/@openidentityplatform/*` was reinstalled from those tarballs, and
`openam-ui-ria/target/compiled` was rebuilt by `npx vite build`. All three are gitignored build
products and all three now hold exactly what the unmodified sources produce.

---

## 12. What this scan does NOT cover - the boundary

This is the record of a scan over **application source**. It is deliberately not a claim about
anything below, and a reader inheriting task 8.3 should treat each of these as still open.

1. **`node_modules` is out of scope, and it is where the remaining lodash-4 breakage lives.**
   `vite.config.js` aliases both `lodash` **and** `underscore` to the vendored 3.10.1 file.
   `backbone@1.1.2` and `backgrid@0.3.5` call 31 removed APIs between them (S6.1). Nothing in this
   scan touches them, and no source edit can: **the owner is 8.3's alias decision.**
2. **The five Backbone-collection call sites are still there, on purpose.**
   `CommonShare.js:165, 236, 241`, `ResourcePage.js:219` and `EditRequest.js:112` call
   `Collection.pluck` / `Collection.findWhere`, which are **Backbone methods, not lodash**, so they
   are not sites in this table - but `Backbone.Collection.prototype.pluck` is
   `_.invoke(this.models, "get", attr)` internally and breaks under lodash 4 for the reason in
   S6.1. The superset grep in S12.1 shows them, and they are the only removed-API-shaped names it
   still finds. **8.3's problem.**
3. **Vendored libraries under `src/main/js/libs/` were scanned and excluded.** Zero lodash calls of
   any kind in all eleven files (S6.2). `lodash-3.10.1-min.js` is not deleted here - 8.3 owns it.
4. **`src/test/` in all three repos is outside this scan's fix scope.** It was checked anyway:
   **zero removed-API calls** across all 42 test files, so nothing is being deferred silently.
5. **No lodash version moved, and no dependency was added.** `package.json`, `package-lock.json`
   and `vite.config.js` are all untouched by 8.2 - verified, `package-lock.json` shows no diff.
   The browser still runs lodash 3.10.1. **That is exactly why every replacement had to be
   both-major safe**, and it is what makes 8.3's flip a version change rather than a rewrite.
6. **This is verified by construction and by the build, not by coverage.** Of the 70 sites, the
   commons Vitest suite executes **7** (`ObjectUtil.js:37, 52, 205, 252, 255, 265` via
   `toJSONPointerMap`/`generatePatchSet`/`AbstractModel > patch operations`, and
   `ValidatorsManager.js:47`). Nine more have AM Karma specs that **cannot run today** (S8.3):
   `JSONSchema.js:61, 101`, `JSONValues.js:45, 72`, `RealmHelper.js:134`,
   `ThemeManager.js:108, 121`, `query.jsm:29`, and the two new predicate fixes `JSONSchema.js:238`
   and `JSONValues.js:155`. The remaining **52 have no test at all** - including all five Pass-5
   chain sites, two of which (`TabComponent.js`, `NavigationHelper.jsm`) are on the admin console's
   boot path, so under lodash 4 they would have produced a blank page rather than a degraded one.
   That is
   the honest coverage figure; restoring the Karma runner is D12 / group 9, not group 8.
7. **Playwright was not run**, deliberately: the runtime lodash has not moved, so a spec run would
   be re-asserting 8.1's state, and it needs a deployed AM (8.3). S8.4 lists which specs drive
   which screens; it does not claim coverage of these lines.
8. **`openidm-ui` and `openig-ui` carry 61 removed-API calls of their own** (S5). None of that is
   group 8's, and none of it is touched - but it is why the commons half of this change had to stay
   both-major.
9. **`_.pick` / `_.omit` with a *key list* gained path semantics in lodash 4, and that class is not
   fixed here.** lodash 4 resolves a key containing `.` or `[` as a **path** unless the string is an
   own property of the target object (`isKey()` short-circuits on `key in Object(object)`). Every
   site this task *rewrote* is safe by construction, because each draws its keys from
   `_.keys(<the same object>)`. Sites that take their keys from a **different** object are not, and
   were left alone: `AM admin/models/Form.js:98`, `AM .../JSONEditorView.js:138`,
   `AM .../JSONValues.js:98, 184, 186`, `AM .../EditPolicyView.js:274`,
   `AM .../EditResourceTypeView.js:164`, `AM user/login/RESTLoginHelper.js:164`,
   `CMN components/ChangesPending.js:91`. Measured divergence when a key is absent-but-path-shaped:
   `_.pick({a:{b:9}}, ["a.b"])` gives l3 `{}` / l4 `{a:{b:9}}`, and the `omit` form additionally
   **mutates** the nested value to `{a:{}}`. Whether this can fire depends on whether AM schema
   property names can contain a dot; that was not established here. **8.3 should settle it.**
10. **`JSONSchema.pick` and `JSONValues.pick` still call `_.pick(object, predicate)` directly.**
    They are safe *today* only because no caller passes a function - `JSONSchema.js:187` passes a
    string and `JSONEditorView.js:138` passes an array, both confirmed by reading the callers. The
    parameter is nonetheless named `predicate`, and the sibling `omit` methods now route through
    `omitByPredicate`. If a caller ever passes a function these fail silently, the same way
    `JSONValues.omit` did. Deliberately not changed, because changing it would alter no behaviour.

### 12.1 The assertion that makes 8.3 safe

Over `OpenAM/openam-ui/openam-ui-ria/src/main/js`, `commons/ui/commons/src/main/js`,
`commons/ui/user/src/main/js` and `commons/ui/mock/src/main/js`, excluding `libs/`, `node_modules`
and `target/`. **A grep alone is not the assertion** - it is anchored on `_.<name>`, so it cannot
see the wrapper-only removal (`run`) or any of the Pass-5 chain-terminator sites. All three checks
below are needed, and all three are clean.

**(a) the 31 top-level removed names:**

```
$ grep -rnE '(^|[^A-Za-z0-9_$.])_\.(all|any|backflow|callback|collect|compose|contains|detect|findWhere|foldl|foldr|include|indexBy|inject|methods|modArgs|object|padLeft|padRight|pairs|pluck|restParam|select|sortByAll|sortByOrder|support|trimLeft|trimRight|trunc|unique|where)\b' \
    --include='*.js' --include='*.jsm' --include='*.jsx' --include='*.mjs' --include='*.html' \
    --exclude-dir=libs --exclude-dir=node_modules --exclude-dir=target \
    <the four trees>
$ echo $?
1
```

No output. The superset grep for the **chained** forms (`.<removedName>(` with no `_.` anchor)
returns 56 lines, and every one reconciles: `Promise.all`, the service layer's own `.all()`
methods, jQuery `.select()`, and the five Backbone-collection calls named in item 2 above. **Zero
lodash calls.**

**(b) `run`, the 32nd name - removed from the lodash 4 wrapper, invisible to (a):**

```
$ grep -rnE '\.\s*run\s*\(' --include='*.js' --include='*.jsm' --include='*.jsx' --include='*.mjs' \
    --exclude-dir=libs --exclude-dir=node_modules --exclude-dir=target <the four trees>
$ echo $?
1
```

No output.

**(c) the Pass-5 assertion, which no grep can make.** 71 files contain a call to one of the 11
methods that terminate a chain under lodash 4; what matters is only whether an implicit `_(x)`
chain **continues past one**. That is a parser question, and the AST pass answers it: over all
**367 files, zero** such chains remain (was 4 files / 5 calls). Reproduce with the Pass-5 probe in
S1.6 plus the chain walk in the rescan script.

### 12.2 Verification run for 8.2

An earlier revision of this table recorded "redefined classes, post-edit: **0** defects" while 8
sites were still live, because the scan could not express the two classes in S1.6. That row was
wrong, and a false all-clear on the document 8.3 acts on is worse than a missing row. The rows
below are the corrected run, after Pass 4 and Pass 5 were added to the method.

| check | result |
|---|---|
| AST re-scan, removed APIs (32 names, incl. `run`), post-edit | **0** sites (was 18 + 1) |
| AST re-scan, non-call / computed references | **0** |
| AST re-scan, redefined classes, post-edit | **0** defects; the 2 `_.escape` hits are the compensated calls |
| AST re-scan, **Pass 5** chain continues past a lodash-4 terminator | **0** (was 4 files / 5 calls) |
| AST re-scan, **widened** `pick`/`omit` predicate check | 11 candidates, **0** defects - each resolved by reading the caller (S1.6) |
| every changed file re-parsed with `@babel/parser` | 35/35 clean |
| differential re-run of the 8 late fixes, old-l3 vs new-l3 vs new-l4 | **11/11 `SAME`** |
| `commons` `npm run test:esm` | **9 files, 32 tests passed** |
| `commons` `npm run verify:esm` | **16/16 checks passed** |
| `user` `npm run test:esm` | **1 file, 15 tests passed** |
| `user` `npm run verify:esm` | **8/8 checks passed** |
| commons -> AM chain (S7 steps 1-4) | `build:npm` x2, `npm pack` x2, one install of **both** tarballs, exit 0 |
| `npx vite build` in `openam-ui-ria` | **exit 0**, built in 10.13 s |
| `openam-ui-ria/package-lock.json` | **unchanged** (`git diff --stat` empty) |
| `@openidentityplatform/ui-commons` / `ui-user` | both resolve, `3.2.0-SNAPSHOT` |
| `vite` | `node_modules/vite/index.cjs`, **5.4.21** |

---

## The flip (task 8.3)

*Measurement pass, 2026-09-02. Nothing in this section was applied: no lodash version moved, no
alias changed, `src/main/js/libs/lodash-3.10.1-min.js` was not deleted and `design.md` was not
edited. What follows is the ground truth the apply run needs.*

### F1. Preconditions, all five confirmed

`OpenAM` on `features/openam-ui-migration`; `commons` on `features/ui-migration`; tasks 8.1 and 8.2
both `[x]`; `NOTES-lodash-4.md` present and tracked; `openam-idp` and `opendj-idp` both Up and
healthy. The AM container is a **fresh provision**, so its `/XUI` was the pristine tree shipped in
`OpenAM-16.2.0-SNAPSHOT.war`, not a build left behind by task 7.5 — see F10.

### F2. THE REFERENCE LANE RUN — 57 passed / 8 failed / 1 skipped

Built with a bare `npx vite build` (exit 0, 11.24 s, "copied 263 static files verbatim and 38
runtime libraries … stamped index.html with version dev"), deployed with
`e2e/local/xui-deploy.sh target/compiled` (900 files), then, from `OpenAM/e2e`:

```
npx playwright test xui/ --reporter=line --trace=off > /tmp/8.3-lane-reference.txt 2>&1
```

`Running 66 tests using 1 worker` → **8 failed, 1 skipped, 57 passed (4.3m)**.

| # | Spec | Why | Known? |
|---|---|---|---|
| 1 | `xui-cache-busting.spec.mjs:106` — a template fetched at runtime carries the build version | `index.html must configure RequireJS urlArgs as v=<version>`, received `null` | **known**, 7.5 |
| 2 | `xui-cache-busting.spec.mjs:144` — `require.toUrl()` applies the configured urlArgs | same RequireJS `urlArgs` form Vite no longer emits | **known**, 7.5 |
| 3 | `xui-operator-module.spec.mjs:461` — an operator module named in the built configuration is loaded | tree "was not built naming `config/E2EStandInLoginHelper` as its loginHelperClass"; needs `LOGIN_HELPER_CLASS` | **known**, 7.5 |
| 4 | `xui-operator-module.spec.mjs:491` — login and logout still complete through the operator's module | same | **known**, 7.5 |
| 5 | `xui-theming.spec.mjs:662` — each realm gets the stylesheets of the theme it is mapped to | "The deployed /XUI was not built with `THEME_CONFIG_OVERRIDE`", prints the rebuild command | **known**, by design |
| 6 | `xui-theming.spec.mjs:688` — each realm gets the login logo of the theme it is mapped to | same precondition | **known**, by design |
| 7 | `xui-theming.spec.mjs:820` — a template the theme supplies replaces the default one | same precondition | **known**, by design |
| 8 | `xui-theming.spec.mjs:838` — a template the theme does not supply still renders from the default path | same precondition | **known**, by design |

Skipped: `xui-httponly.spec.mjs:186`, `test.skip(!httpOnly, …)` — the instance is not in HttpOnly
mode. **No login test failed**; `xui-login.spec.mjs:123`'s intermittent did not fire on this run.

**NEW REDS: none.** Every one of the eight matches a case already recorded by 7.5 or by the spec's
own by-design precondition.

**The divergence from 7.5's 61/4/1 is the build command, not the provisioning and not a
regression.** 66 tests both times, and the four extra reds are exactly the four theming specs,
each failing on `THEME_CONFIG_OVERRIDE` being absent from the build. 7.5's tree was built with that
override; this one was built with a bare `npx vite build` because that is what the task asked for.
Rebuild with the override and this lane is 61/4/1. The fresh provision is visible nowhere in the
result — it is visible only in F10.

### F3. WHAT "GREEN EITHER SIDE" CAN MEAN — position

**It cannot mean zero failures, and it must mean no delta — against a named list of expected
failures, not against a summary line.** Three independent reasons, all measured above:

1. 7.5 already recorded, as an open item with no owner, that **no single deployed tree can make
   this lane green today**. The two cache-busting specs assert a RequireJS `urlArgs` form Vite
   structurally cannot emit, so they are red against *every* Vite build. Zero-failures is not a
   bar 8.3 can clear by doing 8.3 correctly; it is a bar nothing can clear.
2. The failure *count* is a function of build flags, not of lodash. This pass got 8; the same
   source with `THEME_CONFIG_OVERRIDE` gets 4; with `LOGIN_HELPER_CLASS` as well it would get 2 —
   and task 7.2's assertion plugin forbids shipping that flag. A summary line therefore compares
   two build invocations, not two lodash versions, and can differ by four while nothing regressed
   or be equal while something did.
3. Per-spec *counts* are only marginally better: they would catch a spec moving from pass to fail
   but not a swap, and they still move with the flags.

So the comparable unit is **the set of failing test ids** — `<file>:<line> › <title>` as the line
reporter prints them — from two runs **made with the same build command against the same
container**, and the acceptance is set equality. Concretely, for the apply commit: build both
sides with the identical command, and require that the before-run and after-run produce the same
eight ids as F2's table (or the same four, if the change owner prefers the flagged build). Any id
appearing in the after set and not the before set is 8.3's; any id leaving it is a bonus to be
explained, not silently banked. **This is the change owner's call and the notes do not decide it —
F3 is a recommendation.**

### F4. THE REFERENCE INVENTORY — every place the file and the two aliases are named

`src/main/js/libs/lodash-3.10.1-min.js` (md5 `7629cac4`, 50,543 B) and the `underscore` / `lodash`
`resolve.alias` entries. Grep basis: `git grep -n "lodash-3\.10\.1"` over both repositories, plus
`grep -n 'find: "underscore"\|find: "lodash"'`.

**Code and configuration — 8.3 acts on these**

| Where | What it is | 8.3 |
|---|---|---|
| `vite.config.js:3041` | `{ find: "underscore", replacement: fromSrc("libs/lodash-3.10.1-min.js") }` | **CHANGE — retarget, do not delete.** 28 `from "underscore"` statements survive in the emitted `ui-commons`/`ui-user` ESM trees, and `libs/backgrid-paginator-0.3.5-custom.min.js:8` does `require("underscore")`. See F5 for the form. |
| `vite.config.js:3058` | `{ find: "lodash", replacement: fromSrc("libs/lodash-3.10.1-min.js") }` | **DELETE.** Bare `lodash` then resolves through normal node resolution to `node_modules/lodash`. Deleting it also retires the prefix-capture hazard the entry's own comment records at `:2825` (`find: "lodash"` is a prefix match, so `lodash/fp` was being rewritten to `<abs>/lodash-3.10.1-min.js/fp`). |
| `src/main/js/shims/backgrid-globals.js:11` | `import _ from "../libs/lodash-3.10.1-min.js";` — **a hard-coded relative path in product source**, not an alias | **CHANGE** to `import _ from "lodash";`. This is the one that does not show up if you only look at the alias table, and it hard-fails the build (missing file) rather than failing silently. |
| `package.json:89` | `lodash: "4.18.1"` in **devDependencies** | **CHANGE** — move into `dependencies` at the same exact pin. Every entry in `dependencies` is already an exact pin (33 of 33, checked), so `4.18.1` matches house style. Nothing in `vite.config.js` asserts the `dependencies` block, and `VENDORED_VERSION_CHECKS` covers only the two `eonasdan-bootstrap-datetimepicker` files, so no build assertion needs updating. |
| `src/main/js/libs/lodash-3.10.1-min.js` | the vendored file | **DELETE** |
| `src/main/js/libs/README.md:60` | the register row `| lodash-3.10.1-min.js | 7629cac4 | 50,543 | lodash 3.10.1 | MIT | 4.3 |` | **DELETE the row**, and update the prose at the head of the file: it says the binding is "a `resolve.alias` entry in `vite.config.js` (the **ten** library files)" — that becomes nine. |
| `src/test/js/test-main.js:53` | `"lodash": "libs/lodash-3.10.1-min"`, a RequireJS `paths` entry | **CHANGE** (one line) or record as knowingly stale. The runner is dead today — `npm test` is a stub that echoes and exits 0, and `test:karma` (`grunt karma:build`) fails on the composed tree before any assertion; D12 / group 9 owns restoring it. But leaving a `paths` entry pointing at a deleted file is a trap for whoever does. |
| `src/test/js/test-main.js:30` | `"underscore": "lodash"` in the AMD `map` block | **LEAVE ALONE.** It maps a logical name onto the `paths` key above and stays correct whatever that key points at. |
| `vite.config.js` comments at `:374`, `:2825`, `:3002-3058`, `:3784`, `:3799`, and the SCOPE paragraph above `:3841` | prose that names the file, the split, and what 8.3 does | **CHANGE.** In particular the SCOPE paragraph is wrong — F5. |

**Names it that 8.3 must NOT touch**

| Where | Why leave alone |
|---|---|
| `src/main/js/moduleRegistry.js:122` | The AM glob is `"/src/main/js/**/*.{js,jsx,jsm}"` — a wildcard. It never names lodash; deleting the file just removes a dead key from the registry map. No edit, and no build assertion counts those keys. |
| `Gruntfile.js:20` — `var _ = require("lodash")` | The **build script's** own use of the npm package, already 4.18.1. Moving the declaration from `devDependencies` to `dependencies` does not change what resolves here. |
| `PHASE1-TREE.md:268` | The Grunt-tree digest oracle, a historical record of what Grunt shipped. It is not read by the build. F6. |
| `OpenAM/legal/THIRDPARTYREADME.txt:878` | Product legal notice for the whole distribution. Out of a build change's scope; flag to the change owner rather than editing. |
| `commons/ui/mock/src/main/js/main.js:46` — `lodash: "libs/lodash-3.10.1-min"` | The AMD/QUnit harness, fed by the `commons.ui:*:zip:www` channel that still ships 3.10.1. Touching it would move the AMD side of the dual build, which is not 8.3's. |
| `commons/ui/AMD-PARITY.md:582`, `commons/ui/LIBS-INVENTORY.md:287` | Records of the Maven channel as it is. |
| `commons/ui/{commons,user}/package-lock.json` | Lockfile entries for each module's own `lodash` **devDependency** 3.10.1 — see F9, which does not move. |
| every `NOTES-*.md` hit | Prior tasks' records. |

### F5. WHAT MUST NOT BE DELETED ALONGSIDE — vite.config.js contradicts itself, and the later half is right

`build.commonjsOptions.include` is `[/node_modules/, /src[\\/]main[\\/]js[\\/]libs[\\/]/]`
(`vite.config.js:3842`). The comment above it makes **two claims that cannot both hold**:

* the 4.3 SCOPE paragraph: *"Task 8.3 deletes both the file and this entry when lodash 4 lands."*
* the 5.2 paragraph immediately below it: *"Narrowing this regex to the one lodash file, or
  deleting it when task 8.3 removes lodash, breaks all five silently — the ids still RESOLVE, and
  the imported value is simply undefined."*

**The SCOPE sentence is WRONG. Do not delete the second pattern.** It is stale: 4.3 wrote it when
lodash was the only consumer, and 5.2 added five more without rewriting it. Verified from the
alias table rather than from the comment — each of these resolves to a UMD/CommonJS file under
`src/main/js/libs/` that has no ES exports without the transform:

| id | resolves to |
|---|---|
| `form2js` | `libs/form2js-2.0-769718a.js` (`vite.config.js:3457`) |
| `js2form` | `libs/js2form-2.0-769718a.js` (`:3458`) |
| `bootstrap-datetimepicker` | `libs/bootstrap-datetimepicker-4.14.30-min.js` (`:3460`) |
| `backgrid.paginator` | `shims/backgrid-paginator.js` (`:3445`) → `import "../libs/backgrid-paginator-0.3.5-custom.min.js"` |
| `jsonEditor` | `shims/json-editor.js` (`:3433`) → `import "../libs/jsoneditor-0.7.23-custom.js"` |

**8.3's edit here is to the prose only**: strike the SCOPE sentence's "and this entry", and record
that after the flip lodash reaches the transform through the *first* pattern (`/node_modules/`),
because `node_modules/lodash@4.18.1` is CommonJS — `main: lodash.js`, no `module` field, no
`exports` map (checked in the installed tree). A wrong deletion here is silent by construction:
the five ids keep resolving and every import of them becomes `undefined`.

**The alias form after the flip.** Aliases do not chain in Vite — that is the reason 4.3 refused to
write `{ find: "underscore", replacement: "lodash" }`, because `"lodash"` would be handed to normal
node resolution and land on 4.18.1 in `node_modules`. **At 8.3 that is exactly the wanted target**,
so the entry 4.3 refused becomes the correct one. `assertAliasOrdering` permits it: it only rejects
duplicate `find` patterns and a later pattern shadowed by an earlier `<earlier>/` prefix, and
imposes nothing on the replacement. Either write `{ find: "underscore", replacement: "lodash" }` and
let node resolution do it, or keep the existing one-hop-absolute idiom with
`requireFromConfig.resolve("lodash")`; the second is more consistent with the file's other entries
and fails loudly at config load if the package is missing.

### F6. ZIP IMPACT — one file, and no build assertion goes stale

`src/main/assembly/zip.xml` is a single `<fileSet>` of `target/compiled` onto `/`, so the www zip
is the built tree verbatim.

* **Built `/libs` before:** 38 files, including `lodash-3.10.1-min.js`. **After:** 37. lodash 4
  arrives as a bundled npm import and gets **no** `/libs` entry — it has no `NPM_LIBRARY_FILES`
  key and `copyLibraries` only walks `libs/` directories under the composition sources.
* **Built tree before:** 900 files. **After:** 899. The www zip loses exactly
  `libs/lodash-3.10.1-min.js` and gains nothing.
* Worth stating plainly: **the shipped `/libs/lodash-3.10.1-min.js` is already dead weight today.**
  Both aliases point at the *source* copy, which Rollup bundles into the hashed chunks; nothing in
  the built tree fetches the `/libs` copy. Deleting it removes a file no deployed page loads.
* **No count assertion goes stale.** `grep` for hard-coded totals in `vite.config.js` finds none —
  the "263 static files … 38 runtime libraries" line is a `console.log`, not an assertion, and the
  only library-shape guard is `copyLibraries`'s duplicate-supplier throw plus 4.8's CodeMirror
  literal-path check, neither of which counts anything.
* `PHASE1-TREE.md` records **652 files** and carries `7629cac4f079926ef505e2271bb5135f  50543
  libs/lodash-3.10.1-min.js` at line 268. It is the **Grunt** tree's digest — the acceptance oracle
  for phase 1, a record of what Grunt shipped — not a description of the Vite tree and not read by
  any build step. It does not go stale, because it was never a claim about the post-flip tree.
  Leave it untouched.

### F7. THE VERSION — recommend **4.18.1**, and it is the only clean choice

`npm view lodash dist-tags` → `latest: 4.18.1`. Versions near the candidates, from
`npm view lodash versions`: … `4.17.20`, `4.17.21`, **`4.17.23`** (there is no `4.17.22`),
`4.18.0`, `4.18.1`. `npm audit`, run per candidate in a throwaway tree:

| version | `npm audit` |
|---|---|
| `4.17.21` | **1 high** — `lodash <=4.17.23`: code injection via `_.template` imports key names (GHSA-r5fr-rjxr-66jc), prototype pollution via array-path bypass in `_.unset`/`_.omit` (GHSA-f23m-r3pf-42rh), prototype pollution in `_.unset`/`_.omit` (GHSA-xxjr-mmjv-4gpg). Fix is `4.18.1`. |
| `4.17.23` | **1 high** — the first two of the three above. Fix is `4.18.1`. |
| `4.18.0` | **found 0 vulnerabilities** |
| `4.18.1` | **found 0 vulnerabilities** |

**Recommendation: `lodash` `"4.18.1"`, exact, moved into `dependencies`.** It is `latest`, it is the
only pair of clean versions' upper half, and it is *already* the number in this module's
`package.json` and `package-lock.json` — so the flip changes which dependency block the line lives
in and deletes a vendored file, rather than also moving a version. That keeps the commit reviewable,
which is the whole point of 8.3 being its own commit. Note the register's own bar: once lodash comes
from npm it is back inside `npm audit`'s view, which is the exception D20 exists to shrink.

*One caution the apply run should carry, not resolve:* 4.18.0 is the release that **fixed**
`_.omit`/`_.unset` array-path handling. AM has 13 `_.omit` call sites, all of them key-list or
routed through 8.1's `omitByPredicate` helper, so none is a predicate call; but the path-semantics
class in §10 item 9 is about key lists, so 4.18 is the version whose behaviour that item should be
re-read against. See F11.

### F8. THE TWO PEER RANGES

`commons/ui/commons/package.json` and `commons/ui/user/package.json` both declare
`"lodash": ">=3.10.1"` under `peerDependencies`, with a long `//peerDependencies-lodash` note in
each. Both notes give the same reason for the width — *"the source is written against lodash 3
semantics and 8.1 has not yet replaced the 25 call sites"* — and ui-user's adds that the two
packages must state the same range *"or the conflict simply moves"*.

**Both should become `"^3.10.1 || ^4.0.0"`, identically, and both notes should be rewritten to say
that 8.1/8.2 landed and that the range is now a two-major compatibility claim rather than a
placeholder.** `>=3.10.1` should not survive: it also admits lodash 5, which nothing has tested.
The replacement must still satisfy **both** `4.18.1` (so the packed tarball still installs into
openam-ui-ria, which is what `>=` was protecting — measured as ERESOLVE in the 3.7 pass) **and**
`3.10.1` (see below). §9 of this file reached the same conclusion; F8 confirms it against the files.

The notes' rewrite also has to fix two things §9 already flagged: the count is **91 sites, not 25**,
and "APIs lodash 4 removed" understates the job — 44 of the 91 use an API lodash 4 still exports
under the same name with different behaviour.

**Does narrowing break `openidm-ui` or `openig-ui`? — FLAGGED, NOT DECIDED.** Two separate things,
and they should not be conflated:

* *The range itself cannot break them.* Both consume commons through
  `commons.ui:*:zip:www` — a Maven artifact. Maven does not read `peerDependencies`; npm peer
  resolution is not in their build at all. `^3.10.1 || ^4.0.0` is satisfied by 3.10.1 anyway, so
  even if it were read, it admits them.
* *The shared source can.* Those products bind `libs/lodash-3.10.1-min` in their own `main.js`
  (`OpenIG/openig-ui/src/main/js/main.js:46` and the openidm equivalent; `commons/ui/pom.xml:85-90`
  still ships 3.10.1), and 8.1/8.2 rewrote commons **source** that flows into their zips. §5 of this
  file records that every one of the 91 replacements behaves identically under both majors, and F9
  is direct evidence for the commons half. **That claim is what protects them, not the range.** The
  decision to put to the change owner is therefore not "may we narrow the range" but "do we accept
  §5's both-major claim as the standing guarantee for the two products this change never builds or
  tests" — and, if so, whether that guarantee gets written down somewhere the next lodash bump will
  find it. `openidm-ui` and `openig-ui` additionally carry **61 removed-API calls of their own**
  (§10 item 8) which are nobody's in this change.

### F9. DEVDEP — **no**, neither has to move

`commons/ui/commons` and `commons/ui/user` each declare `lodash: "3.10.1"` in `devDependencies` and
each has it installed at 3.10.1. Both suites were run against those trees on this pass, unmodified:

| module | `npx vitest run` |
|---|---|
| `commons/ui/commons` | **9 test files, 32 tests, all passed** (3.72 s) |
| `commons/ui/user` | **1 test file, 15 tests, all passed** (1.92 s) |

Both run against the **emitted** `target/npm/esm` tree, so this is evidence about what the packages
ship. So the answer to "does the devDependency have to move for the suites to keep passing" is a
measured **no** — 8.1/8.2's rewrites are lodash-3-clean, which is what §5's both-major claim
predicted.

**But leaving it at 3.10.1 means the suites only ever prove the lodash 3 half of the widened range.**
That is a coverage gap, not a breakage, and it is a real choice for the change owner: bump both
devDependencies to 4.18.1 and the suites prove the half the range newly asserts while losing the
half `openidm-ui`/`openig-ui` actually run; leave them and the new half of `^3.10.1 || ^4.0.0` is
asserted by nobody. The honest third option is a matrix run. **8.3 should not decide this silently
by editing the pin.**

### F10. CONTAINER

**Found:** the pristine Grunt/RequireJS tree baked into `OpenAM-16.2.0-SNAPSHOT.war` and expanded by
Tomcat — 19 top-level entries with `main.js` + `main.js.map`, **no `assets/`**, `index.html` ending
in the `var require = { urlArgs : "v=16.2.0-SNAPSHOT", deps : ['main'] }` block, `libs/` carrying 47
entries including `lodash-3.10.1-min.js`, owner `openam:root`. `XUI/index.html` is sha256
`961345a9af3f523af921b73f8f5501d1fa212b0a9ed378c79127961b97bee4d7`, `config/AppConfiguration.js`
`343bee5c…`, `main.js` `cd9c73e5…` — **the same three digests `NOTES-operator-module-d6.md` §9.2
recorded**, so this fresh provision is byte-identical to the tree that task documented. It was NOT a
tree left by 7.5.

**Procedure:** `NOTES-operator-module-d6.md` §9.1 verbatim, no second procedure invented.
`docker exec openam-idp sh -c 'cd /usr/local/tomcat/webapps/openam && tar czf - XUI'` → a 2,014,209 B
/ 855-entry tarball, taken **before** the deploy. A full-tree manifest was taken at the same moment:
`find . -type f | LC_ALL=C sort | xargs sha256sum`, **652 files**, manifest sha256
`4d73ab619d3bf0ac16e58352b1885b95b560f6ecf49b31aa0e43cc86367ac3ca`.

**Mutated:** deployed the Vite tree (900 files) for the F2 lane run.

**Restored and verified:** `rm -rf` then `tar xzf` from the tarball as root. The same full-tree
manifest was retaken afterwards and is `4d73ab61…` — **byte-for-byte identical, all 652 files**,
`diff` clean. 19 top-level entries, owner `openam:root`, mtimes preserved. Live checks:
`GET /XUI/index.html` 200 and still serving `urlArgs : "v=16.2.0-SNAPSHOT"`;
`GET /XUI/libs/lodash-3.10.1-min.js` 200; `GET /XUI/assets/` **404**, so no Vite output survives.
`openam-reset.sh` was not needed and was not run; no container was rebuilt or restarted.

**At exit the deployed `/XUI` is the shipped Grunt/RequireJS build, exactly as found.**
`openam-ui-ria/target/compiled` holds a clean unflagged Vite build (gitignored). No tracked file was
modified other than this one. Throwaway scripts: none created.

### F11. SETTLED HERE — §10 item 9's open question: **yes, AM property names contain dots**

Item 9 says the `_.pick`/`_.omit`-with-a-key-list path-semantics class "depends on whether AM schema
property names can contain a dot; that was not established here. **8.3 should settle it.**"
Established against the running instance:

`GET /json/global-config/servers/server-default/properties/advanced` returns **104 keys, and all 104
contain a dot** — `com.iplanet.am.directory.ssl.enabled`, `openam.auth.distAuthCookieName`,
`com.sun.identity.webcontainer`, and so on. Its `?_action=schema` returns **zero** `properties`, i.e.
this view is a free-form key/value map with no per-key schema, handled by `JSONValues` rather than
`JSONSchema` — and `JSONValues.js:98, 184, 186` are three of the nine sites item 9 lists as *not*
safe by construction.

**So the hazard class is live, not theoretical.** What it does *not* establish is that the
divergence fires: this file's own table (line 732) measured that a dotted key which **is** an own
property behaves the **same** under both majors, because lodash 4's `isKey()` short-circuits on
`key in Object(object)`. The divergence needs a key that is dotted **and absent** from the target.
The residual question is therefore narrowed to: *at the nine sites that draw keys from a different
object, can a dotted key be absent from the object being picked or omitted?* That is a code-reading
question over nine call sites, it is now the only part of item 9 still open, and F7's caution about
4.18.0 being the release that changed `_.omit` array-path handling points at the same nine.

### F12. Still open after this pass

1. **§10 item 9's residual**, narrowed by F11 to nine named call sites. Not chased here.
2. **Whether the commons devDependencies move** (F9) — a coverage choice, deliberately not taken.
3. **Whether §5's both-major claim is accepted as the standing guarantee for `openidm-ui` and
   `openig-ui`** (F8) — the change owner's, flagged not decided.
4. **F3's acceptance unit** — recommended, not decided.
5. **`OpenAM/legal/THIRDPARTYREADME.txt:878`** names `lodash-3.10.1-min.js`. Whether a build change
   edits the product legal notice is out of a build task's scope; flagged.
