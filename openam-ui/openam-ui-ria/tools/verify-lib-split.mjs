/*
 * TASK 8.3. Guards the two-library split that task 8.3 created.
 *
 * WHY THIS EXISTS. Before 8.3 the alias table pointed BOTH the `lodash` and the `underscore` ids at
 * one vendored file, so `_` was a single module instance no matter which name a module asked for.
 * 8.3 gave them different libraries -- lodash 4.18.1 for `lodash`, underscore 1.13.8 for
 * `underscore`, because backbone 1.1.2 and backgrid 0.3.5 need 19 names lodash 4 removed. That is
 * the right call, but it silently converts a whole class of previously-impossible bug into a
 * possible one: a name that is present on ONE instance and absent on the other.
 *
 * The e2e suite cannot see this class. Task 8.3's acceptance gate was set-equality of failing
 * Playwright ids, and it came out identical before and after while three real regressions sat in
 * the diff -- `_.mixin` registering helpers on underscore that five lodash-bound modules read,
 * `window._` handing lodash 4 to a library written against underscore, and `_.get` given a dotted
 * string path that underscore never splits. None of the three is on a page the suite visits.
 * A mechanical check finds all of them in about a second, so run it instead of hoping.
 *
 * WHAT IT CHECKS.
 *   1. Every `_.name` a module calls exists on the library that module actually binds -- counting
 *      names added at runtime by `_.mixin`, and attributing those to the mixing module's OWN
 *      binding. This is the check that catches the mixin split.
 *   2. No underscore-bound module passes a dotted string path to `_.get` / `_.has` / `_.result` /
 *      `_.invoke`. underscore's toPath is `isArray(path) ? path : [path]`: it does not split, so
 *      `_.get(o, "a.b")` is always undefined. Array paths work in underscore AND both lodash
 *      majors, so they are the portable spelling.
 *   3. Warns (does not fail) when an underscore-bound module uses a name whose SEMANTICS differ
 *      between the libraries even though the name exists on both. These need a human; the list is
 *      the reason this file is not just a name check.
 *
 * SCOPE. AM's own source plus the two commons packages as they are actually consumed, because the
 * commons modules are bundle inputs here and half the split lives in them.
 */
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const requireFromRoot = createRequire(path.join(ROOT, "vite.config.js"));

const LIB_IDS = ["lodash", "underscore"];

/* Names that exist on both libraries but do not behave the same. Presence checks are blind to
 * these, so they are reported as warnings against underscore-bound code -- that is the side that
 * changed in 8.3, since it used to be served lodash 3.10.1. */
const THIS_ARG = "underscore honours a 3rd thisArg; lodash 4 ignores it";
const DIVERGENT = {
    /* `when` gates the warning on the actual call shape. Without it this list fires on every
     * `_.each` in the tree -- 44 warnings on a clean tree, which is the same as none. */
    each: { why: THIS_ARG, when: (args) => args.length >= 3 },
    forEach: { why: THIS_ARG, when: (args) => args.length >= 3 },
    map: { why: THIS_ARG, when: (args) => args.length >= 3 },
    filter: { why: THIS_ARG, when: (args) => args.length >= 3 },
    reject: { why: THIS_ARG, when: (args) => args.length >= 3 },
    find: { why: THIS_ARG, when: (args) => args.length >= 3 },
    reduce: { why: THIS_ARG, when: (args) => args.length >= 4 },
    sortBy: { why: THIS_ARG, when: (args) => args.length >= 3 },
    groupBy: { why: THIS_ARG, when: (args) => args.length >= 3 },
    countBy: { why: THIS_ARG, when: (args) => args.length >= 3 },
    every: { why: THIS_ARG, when: (args) => args.length >= 3 },
    some: { why: THIS_ARG, when: (args) => args.length >= 3 },
    indexOf: { why: "underscore's 3rd arg is isSorted; lodash's is fromIndex",
        when: (args) => args.length >= 3 },
    uniq: { why: "underscore's 2nd arg is isSorted; lodash 4 takes no iteratee here",
        when: (args) => args.length >= 2 },
    clone: { why: "lodash 3 took a deep flag; underscore and lodash 4 ignore it",
        when: (args) => args.length >= 2 },
    flatten: { why: "underscore flattens deeply by default; lodash flattens one level",
        when: () => true },
    isFinite: { why: "underscore coerces (isFinite(\"2\") === true); lodash does not",
        when: () => true },
    template: { why: "different options shape and different default interpolation",
        when: () => true }
};

/* Split the argument list of a call whose "(" is at `open`, respecting nesting and quotes, so the
 * warnings above can be gated on arity even when the call spans several lines. */
function callArgs (source, open) {
    if (source[open] !== "(") { return null; }
    const args = [];
    let depth = 0;
    let quote = null;
    let start = open + 1;
    for (let i = open; i < source.length; i += 1) {
        const ch = source[i];
        if (quote) {
            if (ch === "\\") { i += 1; } else if (ch === quote) { quote = null; }
            continue;
        }
        if (ch === "\"" || ch === "'" || ch === "`") { quote = ch; continue; }
        if (ch === "(" || ch === "[" || ch === "{") { depth += 1; continue; }
        if (ch === ")" || ch === "]" || ch === "}") {
            depth -= 1;
            if (depth === 0) {
                const tail = source.slice(start, i).trim();
                if (tail || args.length) { args.push(tail); }
                return args;
            }
            continue;
        }
        if (ch === "," && depth === 1) { args.push(source.slice(start, i).trim()); start = i + 1; }
    }
    return null;
}

const PATH_TAKING = new Set(["get", "has", "result", "invoke", "set", "unset"]);

const roots = [
    { dir: path.join(ROOT, "src/main/js"), label: "src/main/js", skip: ["libs"] },
    { dir: path.join(ROOT, "node_modules/@openidentityplatform/ui-commons/esm"), label: "ui-commons" },
    { dir: path.join(ROOT, "node_modules/@openidentityplatform/ui-user/esm"), label: "ui-user" }
];

function walk (dir, skip = [], acc = []) {
    if (!fs.existsSync(dir)) { return acc; }
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) {
            if (!skip.includes(entry.name)) { walk(path.join(dir, entry.name), skip, acc); }
        } else if (/\.(js|jsx)$/.test(entry.name)) {
            acc.push(path.join(dir, entry.name));
        }
    }
    return acc;
}

/* Blank out comments, preserving every offset and newline so reported line numbers stay true.
 * This tree documents vendored libraries by quoting their prologues, so `shims/backbone.js` has a
 * literal `define(["underscore","jquery","exports"], function (i, r, s)` inside a block comment --
 * without this, that comment reads as a real AMD binding and the file is scanned for `i.<name>`. */
function stripComments (source) {
    const out = source.split("");
    let i = 0;
    while (i < source.length) {
        const ch = source[i];
        if (ch === "\"" || ch === "'" || ch === "`") {
            i += 1;
            while (i < source.length && source[i] !== ch) { i += source[i] === "\\" ? 2 : 1; }
            i += 1;
        } else if (ch === "/" && source[i + 1] === "*") {
            while (i < source.length && !(source[i] === "*" && source[i + 1] === "/")) {
                if (source[i] !== "\n") { out[i] = " "; }
                i += 1;
            }
            out[i] = " ";
            out[i + 1] = " ";
            i += 2;
        } else if (ch === "/" && source[i + 1] === "/") {
            while (i < source.length && source[i] !== "\n") { out[i] = " "; i += 1; }
        } else {
            i += 1;
        }
    }
    return out.join("");
}

/* Which library does this module bind, and under what local name? Handles the ESM form the whole
 * tree uses post-4.3 and the AMD form, so the same check can be pointed at commons source. */
function binding (source) {
    for (const id of LIB_IDS) {
        const esm = new RegExp(`import\\s+([A-Za-z_$][\\w$]*)\\s+from\\s+["']${id}["']`).exec(source);
        if (esm) { return { lib: id, local: esm[1] }; }
    }
    const define = /define\(\s*\[([^\]]*)\]\s*,\s*function\s*\(([^)]*)\)/.exec(source);
    if (define) {
        const deps = define[1].split(",").map((d) => d.trim().replace(/^["']|["'],?$/g, ""));
        const params = define[2].split(",").map((p) => p.trim());
        for (const id of LIB_IDS) {
            const at = deps.indexOf(id);
            if (at !== -1 && params[at]) { return { lib: id, local: params[at] }; }
        }
    }
    return null;
}

/* Pull the top-level keys out of `<local>.mixin({ ... })`, brace-matching so nested objects and the
 * JSDoc blocks between entries do not confuse it. */
function mixinKeys (source, local) {
    const keys = [];
    const opener = new RegExp(`\\b${local.replace(/\$/g, "\\$")}\\.mixin\\(\\s*\\{`, "g");
    let match;
    while ((match = opener.exec(source)) !== null) {
        let depth = 1;
        let i = match.index + match[0].length;
        const start = i;
        while (i < source.length && depth > 0) {
            const ch = source[i];
            if (ch === "{") { depth += 1; } else if (ch === "}") { depth -= 1; }
            i += 1;
        }
        const body = source.slice(start, i - 1);
        let d = 0;
        for (const line of body.split("\n")) {
            const trimmed = line.trim();
            /* Keys may be quoted -- the amd2esm output quotes them, the source form does not. */
            const key = /^["']?([A-Za-z_$][\w$]*)["']?\s*:/.exec(trimmed);
            if (d === 0 && key) { keys.push(key[1]); }
            for (const ch of line) {
                if (ch === "{" || ch === "[" || ch === "(") { d += 1; }
                if (ch === "}" || ch === "]" || ch === ")") { d -= 1; }
            }
        }
    }
    return keys;
}

const real = Object.fromEntries(LIB_IDS.map((id) => [id, requireFromRoot(id)]));
const provided = Object.fromEntries(LIB_IDS.map((id) => [id, new Set(Object.keys(real[id]))]));

const modules = [];
for (const { dir, label, skip } of roots) {
    for (const file of walk(dir, skip)) {
        const source = stripComments(fs.readFileSync(file, "utf8"));
        const bound = binding(source);
        if (!bound) { continue; }
        modules.push({ file, label, source, ...bound });
    }
}

/* Pass one: every mixin extends the library its own module binds. Must complete before pass two. */
const mixedIn = [];
for (const mod of modules) {
    for (const key of mixinKeys(mod.source, mod.local)) {
        provided[mod.lib].add(key);
        mixedIn.push({ key, lib: mod.lib, file: mod.file });
    }
}

const errors = [];
const warnings = [];

for (const mod of modules) {
    const rel = path.relative(ROOT, mod.file);
    /* Scan the whole source rather than line by line: a call's arguments routinely span lines, and
     * arity is what gates the semantic warnings. Offsets map back to line numbers here. */
    const newlines = [];
    for (let i = 0; i < mod.source.length; i += 1) {
        if (mod.source[i] === "\n") { newlines.push(i); }
    }
    const lineOf = (offset) => {
        let lo = 0;
        let hi = newlines.length;
        while (lo < hi) {
            const mid = (lo + hi) >> 1;
            if (newlines[mid] < offset) { lo = mid + 1; } else { hi = mid; }
        }
        return lo + 1;
    };

    const usage = new RegExp(`\\b${mod.local.replace(/\$/g, "\\$")}\\.([A-Za-z_$][\\w$]*)`, "g");
    let match;
    while ((match = usage.exec(mod.source)) !== null) {
        const name = match[1];
        const where = `${rel}:${lineOf(match.index)}`;
        const args = callArgs(mod.source, match.index + match[0].length);

        if (!provided[mod.lib].has(name)) {
            const elsewhere = mixedIn.find((m) => m.key === name);
            errors.push({
                where,
                what: `_.${name} is not on ${mod.lib}`,
                why: elsewhere
                    ? `it is mixed into ${elsewhere.lib} by ${path.relative(ROOT, elsewhere.file)}, `
                      + `but this module binds ${mod.lib}`
                    : `this module binds ${mod.lib}, which has no such export`
            });
        }

        if (mod.lib === "underscore" && PATH_TAKING.has(name) && args && args.length >= 2) {
            const literal = /^["']([^"']*)["']$/.exec(args[1]);
            if (literal && literal[1].includes(".")) {
                const segments = literal[1].split(".").map((s) => `"${s}"`).join(", ");
                errors.push({
                    where,
                    what: `_.${name} given the dotted string path "${literal[1]}" on underscore`,
                    why: "underscore's toPath does not split strings, so this is always undefined; "
                         + `use [${segments}]`
                });
            }
        }

        const divergent = mod.lib === "underscore" ? DIVERGENT[name] : null;
        if (divergent && args && divergent.when(args)) {
            warnings.push({ where, what: `_.${name}`, why: divergent.why });
        }
    }
}

const counts = LIB_IDS.map((id) => `${modules.filter((m) => m.lib === id).length} ${id}`).join(", ");
console.log(`verify:lib-split -- ${modules.length} bound modules (${counts})`);
if (mixedIn.length) {
    const summary = mixedIn.map((m) => `${m.key}->${m.lib}`).join(", ");
    console.log(`  mixins registered: ${summary}`);
}

if (warnings.length) {
    console.log(`\n  ${warnings.length} semantic warning(s) -- name exists on both, behaviour differs:`);
    const byName = new Map();
    for (const w of warnings) {
        if (!byName.has(w.what)) { byName.set(w.what, { why: w.why, sites: [] }); }
        byName.get(w.what).sites.push(w.where);
    }
    for (const [name, info] of byName) {
        console.log(`    ${name}  ${info.why}`);
        console.log(`      ${info.sites.join("\n      ")}`);
    }
}

if (errors.length) {
    console.error(`\n  ${errors.length} ERROR(S):\n`);
    for (const e of errors) {
        console.error(`    ${e.where}`);
        console.error(`      ${e.what}`);
        console.error(`      ${e.why}\n`);
    }
    process.exit(1);
}

console.log("\n  OK -- every name resolves on the library its module binds.");
