# `shims/` — what RequireJS's `shim` block used to do

TASK 5.2. These are **this project's own source**, not vendored third-party files: nothing here is
a copy of anything upstream, so D20 and `../libs/README.md` do not apply to this directory.

RequireJS's `shim` block (`main.js:80-172`) encoded two things that an ES module graph does not
express by itself:

1. **`deps` — load order.** RequireJS loaded a shim's `deps` before it even inserted the module's
   `<script>`. Most of that ordering is recovered for free under ESM, because the libraries' own
   CommonJS branches `require()` the same things the shim declared. The cases below are the ones
   where it is **not** recovered, because the dependency is read from a **global** that only the
   AMD/browser branch of the library ever set.
2. **`exports` — the global to pick up.** Only fourteen of the twenty-six entries carry an
   `exports` field at all, and nine of those fourteen were already dead before this task (the file calls `define()`, and RequireJS ignores `exports` then); three
   more resolved to `undefined`. Only `i18next` -> `i18n` and `jsonEditor` -> `JSONEditor` were
   load-bearing, and both are handled here.

Each file except `backgrid-globals.js` is aliased in front of one AMD id in `vite.config.js`'s
`resolve.alias`; `backgrid-globals.js` has no alias, because it is an internal helper that exists
only to give `backgrid-paginator.js` a module boundary to set its globals behind. Importing the
id gets the shim; the shim guarantees the ordering and then hands back what the AMD id used to
resolve to. **The ordering lives in an import edge rather than in configuration**, which is the
whole point: a reader of the shim can see why it exists, and a future `import` of the raw library
cannot silently skip it.

Each shim imports its library by an explicit path (`jquery/dist/jquery.js`, `../libs/<file>`)
rather than by the aliased AMD id, so that no shim depends on the alias table that points at it.
