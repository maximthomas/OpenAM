# Vendored runtime libraries

Third-party JavaScript that ships to the browser but is **not** installed from npm. Everything in
this directory is copied verbatim into the built tree's `/libs` by `copyLibraries` in
`vite.config.js`, under the same filename. Task 5.4 deleted the `require.config.paths` block in
`src/main/js/main.js` that used to bind them by id, so what binds each file now is either a
`resolve.alias` entry in `vite.config.js` (the ten library files) or a literal `<script src>` in a
FreeMarker template outside this Maven module (`requirejs-2.3.7-min.js`, and only that one).

**This directory is an exception to a spec requirement, not the normal route.**
`ui-build-and-packaging` requires that *"third-party JavaScript executed at runtime SHALL be
declared as package dependencies resolved from the public package registry, with exact resolved
versions recorded in a committed lockfile."* Files here satisfy none of that: they are invisible to
`npm audit`, they have no lockfile entry and no integrity hash, and nothing upstream will ever tell
us they have a CVE. Design decision **D20** of the `modernize-openam-ui-build` change records why
the exception exists and what has to be true to add to it.

## Before you add a file here

The bar is that **no npm publication exists under any name**, or that byte-parity with what AM
already ships is required and npm cannot supply it. Both are checkable claims, so check them and
record the result:

1. Search npm for the library under every plausible name, including forks. A package that exists
   but is a *different lineage* is a `replace` decision with a behaviour risk, not a licence to
   vendor — take it to the change owner.
2. If a package exists and only its **built** artifact is missing (npm ships `src/` only), keep the
   dependency declared and vendor the built file. That is the `bootstrap-datetimepicker` shape
   below, and `assertVendoredVersions` in `vite.config.js` then holds the two in step.
3. Add a row to the table below with origin URL, version, md5 and licence as stated in the file.
4. If a real npm package appears later, the row is a removal candidate. That is the exit.

## Line endings are part of the contract

`.gitattributes` marks this directory `-text`, so git stores these files verbatim. Without it
`* text=auto` / `*.js text` normalise CRLF to LF in the blob, and `form2js` and `js2form` — which
are CRLF upstream — come back out of a fresh clone with different md5s than the ones recorded
below and in `PHASE1-TREE.md`. The working tree keeps building; the clone does not match. If you
add a file here, confirm it survives the round trip:

```bash
git cat-file -p :src/main/js/libs/<file> | md5sum   # must equal md5sum of the worktree file
```

## What is here

`Since` is the task that vendored the file. `Licence` is what the file itself states — several are
CDN minifications with the upstream header stripped, and those are marked so rather than guessed.

| File | md5 | Bytes | Origin | Licence in file | Since |
|---|---|---:|---|---|---|
| `backgrid-paginator-0.3.5-custom.min.js` | `ebd4b6db` | 3,915 | local fork of backgrid-paginator 0.3.5 | MIT | pre-existing |
| `bootstrap-datetimepicker-4.14.30-min.js` | `7b418408` | 35,776 | `cdnjs.cloudflare.com/ajax/libs/bootstrap-datetimepicker/4.14.30/js/bootstrap-datetimepicker.min.js` | **not stated** (minified; upstream `Eonasdan/bootstrap-datetimepicker`) | 4.7 |
| `bootstrap-tabdrop-1.0.js` | `7c4081d5` | 5,105 | `www.eyecon.ro/bootstrap-tabdrop/js/bootstrap-tabdrop.js` — **dead domain** | Apache-2.0 | 4.7 |
| `form2js-2.0-769718a.js` | `897ec696` | 10,160 | `raw.githubusercontent.com/maxatwork/form2js/769718a159ff88da82613c2c7e5b1eaa2e0c73e7/src/form2js.js` | MIT | 4.7 |
| `jquery.autosize.input.min.js` | `fa516338` | 1,503 | jquery.autosize.input | **not stated** (minified) | pre-existing |
| `jquery.ba-dotimeout-1.0-min.js` | `f10a418e` | 1,065 | `cdnjs.cloudflare.com/ajax/libs/jquery-dotimeout/1.0/jquery.ba-dotimeout.min.js` | MIT and GPL (dual) | 4.7 |
| `js2form-2.0-769718a.js` | `fc83dc6a` | 9,118 | `raw.githubusercontent.com/maxatwork/form2js/769718a159ff88da82613c2c7e5b1eaa2e0c73e7/src/js2form.js` | MIT | 4.7 |
| `jsoneditor-0.7.23-custom.js` | `6c39c8be` | 138,961 | local fork of jsoneditor 0.7.23 | MIT | pre-existing |
| `lodash-3.10.1-min.js` | `7629cac4` | 50,543 | lodash 3.10.1 | MIT | 4.3 |
| `popover-clickaway.js` | `e92d40fd` | 3,668 | **this project's own source**, not a dependency | CDDL (project) | pre-existing |
| `requirejs-2.3.7-min.js` | `01252f25` | 17,420 | `cdnjs.cloudflare.com/ajax/libs/require.js/2.3.7/require.min.js` | **not stated** (minified; upstream RequireJS is MIT / new BSD) | 4.7 |

One vendored file lives outside this directory, for the same reason and under the same rule:
`src/main/resources/css/bootstrap-datetimepicker-4.14.30-min.css` (`48063c9a`, 7,758 B), from
`cdnjs.cloudflare.com/ajax/libs/bootstrap-datetimepicker/4.14.30/css/bootstrap-datetimepicker.min.css`.
It sits in `resources/css` because that is where the LESS pipeline expects stylesheets, not because
it is a different kind of thing.

## Why each 4.7 row is here

Task 4.7 retired the `commons.ui.libs` Maven channel, which had supplied these as
CDN-fetched-and-republished binary artifacts. Seven files could not follow the rest onto npm:

- **`form2js`, `js2form`** — `form2js` is on npm, but it is a **later fork whose bytes differ from
  the pinned ones by seven lines that change how form fields serialise**, behind `RESTLoginView`
  and five self-service views. Task 3.7 found the divergence. The change owner chose the pinned
  bytes, so both siblings are vendored from the same upstream commit. Full analysis:
  `NOTES-libs-retire.md` §7 and §16.
- **`bootstrap-tabdrop`** — the npm package of that name is `ispot-tv`'s fork, a different lineage
  with no 1.0. The original's `downloadUrl` is a dead vanity domain, so the artifact was already
  unreproducible; vendoring is what makes it reproducible again.
- **`jquery.ba-dotimeout`** — `jquery-dotimeout`, `jquery.ba-dotimeout`, `jquery-ba-dotimeout` and
  `dotimeout` all 404 on npm. There is nothing to replace it with.
- **`requirejs`** — it must exist as a file at a fixed URL no matter what the bundler does,
  because six `.ftl` pages in the **openam-oauth2** Maven module load it with a literal
  `<script src>` before any module system is running, and D8/task 10.4 forbid editing them.
  Byte-exactness is the requirement; see `NOTES-libs-retire.md` §4.1.

  Under task 5.4's option (c1) it is loaded and parsed on those six pages and then does exactly one
  thing: fetch the unhashed classic-script stub the build emits at `main-authorize.js` /
  `main-device.js`, which dynamic-imports the real ES module chunk. It is no longer on any critical
  path and `index.html` no longer loads it at all.

  **`base64` was the second row here and task 5.4 removed it.** Its justification was the same
  sentence as `requirejs`', and the sentence was wrong about it: `index.html:21` was its ONLY
  loader — zero of the six `.ftl` pages mention it — and 5.4 replaced that line with a single
  `<script type="module">`. It is a `btoa`/`atob` polyfill that installs itself only when the
  globals are missing (`r.btoa||(r.btoa=…)`); it defines no `base64` global, no AM module reads
  one, and commons' own `util/Base64` calls native `btoa`/`atob` with a complete pure-JS fallback
  behind a `typeof` test. Every browser that can run `<script type="module">` has both. That is
  D20's removal trigger firing on its own terms — *"a row leaves the register … when the module
  that binds it goes"*.
- **`bootstrap-datetimepicker`** (js and css) — npm publishes `src/` only, no built js and no built
  css. The **dependency is still declared** in `package.json` so the library keeps a lockfile entry
  and stays visible to `npm audit`; only the built bytes are vendored. `assertVendoredVersions` in
  `vite.config.js` fails the build if the declared version and the vendored files' `version :`
  headers ever diverge.
