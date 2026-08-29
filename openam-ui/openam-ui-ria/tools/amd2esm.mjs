/*
 * Purpose-written AMD -> ESM wrapper strip for openam-ui-ria (task 5.4, batches B1-B12).
 *
 * WHY THIS EXISTS RATHER THAN A CODEMOD. @buxlabs/amd-to-es6 0.16.4 was costed first and
 * rejected: it re-prints from the AST and so deletes every comment in the file, including the
 * CDDL licence header, with no preserving option. This transform never re-prints. It slices the
 * original text and splices at three points, so comments, spacing and the licence header survive
 * by construction rather than by effort.
 *
 * SHAPE, per NOTES-amd-to-esm.md section 2b: pair the dep array against the factory params, emit
 * one import per pair, delete the define(...) prologue and the trailing `});`, dedent the body by
 * four, and turn the single top-level `return X;` into `export default X;`.
 *
 * IT REFUSES RATHER THAN GUESSES. Anything outside that shape throws and the file is left for
 * hand work: more than one top-level define, a pseudo-dep (require/exports/module), a
 * non-identifier factory param, more params than deps, more than one top-level return, a bare
 * `return;`. Section 2c counts 49 of 210 files that need hand work for these reasons.
 *
 * WHAT IT DOES NOT DO, and you must still check by hand after each batch:
 *   - `.default` interop unwrapping (section 2c: 36 files, 153 occurrences). An AMD module that
 *     read `dep.default` off an ES dependency must drop the `.default` once the import is real.
 *   - Dependencies whose param is never read. The transform emits a normal import; ESLint then
 *     reports no-unused-vars. Convert those to a side-effect import (`import "id";`) rather than
 *     deleting them -- the AMD load edge may be load-bearing, as ThemeableServerSideFilter in
 *     common/util/BackgridUtils.js is (it registers itself onto Backgrid.Extension).
 *   - `global define` lint pragmas, which become false once define is gone and should go too.
 *
 * USAGE (dry run prints one line per file and writes nothing):
 *     node tools/amd2esm.mjs src/main/js/path/One.js src/main/js/path/Two.js
 *     WRITE=1 node tools/amd2esm.mjs <same files>
 *
 * Always run the dry run first, and always follow a batch with `npm run lint` -- ESLint's
 * indent:[2,4] at error severity is what makes the four-column dedent mandatory rather than
 * cosmetic, so lint is the check that the dedent landed correctly.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";

// resolves acorn from openam-ui-ria/node_modules, wherever the checkout lives
const require = createRequire(import.meta.url);
const acorn = require("acorn");
// acorn (5.x here) cannot read the .jsx and modern .jsm files task 5.1 already emitted;
// the export probe below needs a parser that can, so it uses babel. The TRANSFORM still
// uses acorn -- it only ever parses AMD source, which acorn handles.
const babel = require("@babel/parser");

const PSEUDO = new Set(["require", "exports", "module"]);

/*
 * A `return` only belongs to the nearest enclosing function, so a walk looking for the factory's
 * own returns must not descend into nested ones. `stop` is that boundary (review fix).
 */
const FUNCTION_TYPES = new Set([
    "FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression",
    "ObjectMethod", "ClassMethod", "MethodDefinition"
]);

const walk = (node, fn, stop) => {
    if (!node || typeof node.type !== "string") { return; }
    fn(node);
    for (const key of Object.keys(node)) {
        if (key === "type" || key === "start" || key === "end" || key === "loc") { continue; }
        const value = node[key];
        const descend = (child) => {
            if (stop && child && stop.has(child.type)) { return; }
            walk(child, fn, stop);
        };
        if (Array.isArray(value)) { value.forEach(descend); }
        else if (value && typeof value.type === "string") { descend(value); }
    }
};

/*
 * Guards are LINE ranges, not character offsets. They were offsets, and that was quietly wrong: the
 * caller rewrites `return` to `export default` (+8 chars) and may drop a `;` (-1) BEFORE dedenting,
 * so every offset past those edits was stale by 8. Line indices survive both rewrites, because
 * neither adds nor removes a line.
 */
// eslint max-len for this project; see the import wrapper below
// expression types that become a DECLARATION under `export default`, and so take no trailing `;`
const DECLARATION_EXPR = new Set(["ClassExpression", "FunctionExpression"]);

const MAX_LEN = 120;

/*
 * Node types whose non-computed `key` is a name rather than a reference. Without this,
 * BackgridUtils.js kept a named import for a dependency it never used, because line 231 says
 * `new Backgrid.Extension.ThemeableServerSideFilter(...)` and the property spelling matched the
 * parameter spelling.
 */
const KEYED = new Set([
    "Property", "ObjectProperty", "ObjectMethod", "ClassMethod", "ClassProperty",
    "MethodDefinition", "PropertyDefinition"
]);

const dedent = (text, guardedLines, amount) => {
    const lines = text.split("\n");
    const guarded = (i) => guardedLines.some(([first, last]) => i >= first && i <= last);

    /*
     * With no explicit amount, strip the body's OWN minimum indent rather than a fixed four. Most
     * files sit at a zero base indent so the two agree, but a handful do not: three files in
     * admin/utils and user/login/RESTConfirmLoginView.js have a stray ONE-space base indent, which
     * a fixed four left one column short -- 7 to 11 `indent` errors each, and ESLint was the only
     * thing that noticed. The minimum is taken over non-blank, unguarded lines, so every line it
     * then slices provably has that much leading whitespace to give.
     */
    let pad = amount;
    if (pad === undefined) {
        pad = Infinity;
        lines.forEach((line, i) => {
            if (guarded(i) || !line.trim()) { return; }
            pad = Math.min(pad, line.length - line.trimStart().length);
        });
    }
    /*
     * REVIEW FIX. A single unindented line -- commented-out code at column 0 is the real case --
     * drags the minimum to 0 and the whole body then came out four columns too deep, silently.
     * ScriptsView.js hit exactly this: 212 lines, tool said OK, only ESLint `indent` noticed and a
     * human re-indented it by hand. If the minimum is 0 but the body is overwhelmingly indented,
     * that is the signature of this bug, not of a genuinely flush body, so say so.
     */
    if (pad === 0 && amount === undefined) {
        const live = lines.filter((line, i) => !guarded(i) && line.trim());
        const deep = live.filter((line) => line.length - line.trimStart().length >= 4).length;
        // a genuinely flush body scores ~0; the ScriptsView case scored 0.99. Anything with a
        // majority indented and a computed pad of 0 is this bug, not a flush body.
        if (live.length > 0 && deep / live.length >= 0.5) {
            const flush = lines
                .map((line, i) => [i + 1, line])
                .filter(([i, line]) => !guarded(i - 1) && line.trim() &&
                    line.length === line.trimStart().length)
                .map(([i]) => i);
            throw new Error(
                `dedent refused: ${deep}/${live.length} body lines are indented >= 4 but ` +
                `line(s) ${flush.slice(0, 5).join(", ")} sit at column 0, so the computed pad is ` +
                "0 and the body would be emitted four columns too deep. Re-indent or delete " +
                "those lines (usually commented-out code) and re-run."
            );
        }
    }
    if (!Number.isFinite(pad) || pad <= 0) { return text; }
    return lines.map((line, i) => {
        if (guarded(i)) { return line; }
        // a whitespace-only line keeps no indent of its own, and leaving one is trailing whitespace
        if (!line.trim()) { return ""; }
        // never slice into content: an explicit `amount` can exceed what a given line actually has
        return line.slice(Math.min(pad, line.length - line.trimStart().length));
    }).join("\n");
};

/*
 * The STRING parts of a multi-line template literal must never be dedented -- there the leading
 * whitespace is content, and removing it changes the value.
 *
 * Guard the quasis, NOT the whole TemplateLiteral. The interior of a `${...}` substitution is an
 * ordinary JavaScript expression whose indentation is formatting like any other, so it must be
 * dedented with the rest of the body. Guarding the literal wholesale leaves those lines four
 * columns too deep relative to their new anchor -- exactly what happened to
 * common/util/URLHelper.js in batch B1 and had to be fixed by hand.
 *
 * The line holding the OPENING backtick is not guarded: it starts before the quasi does, so its
 * own leading whitespace is still code.
 */
const templateGuards = (node, src, origin) => {
    const lineOf = (offset) => {
        let line = 0;
        for (let i = origin; i < offset; i++) { if (src[i] === "\n") { line += 1; } }
        return line;
    };
    const guards = [];
    walk(node, (n) => {
        if (n.type !== "TemplateLiteral") { return; }
        for (const quasi of n.quasis) {
            if (src.slice(quasi.start, quasi.end).includes("\n")) {
                guards.push([lineOf(quasi.start) + 1, lineOf(quasi.end)]);
            }
        }
    });
    return guards;
};

/*
 * A dependency on one of AM's OWN ids may point at a module task 5.1 already converted to ESM with
 * NAMED EXPORTS ONLY -- `common/services/ServerService.jsm`, `user/services/SessionService.jsm` and
 * `user/login/tokens/SessionToken.jsm` are the three known ones. The default import this tool emits
 * for them resolves to nothing, and the failure is `"default" is not exported by ...` from the
 * verification build, well after the edit.
 *
 * So warn at transform time instead. This does NOT auto-fix: choosing which named export to take,
 * and what to call it, needs the call sites. Batch B3 hit this twice (SessionService, SessionToken,
 * plus ServerService) on files the census called plain.
 */
const SRC_ROOT = "src/main/js";
const namedOnlyExports = (dep) => {
    /*
     * Probe by PATH, not by id prefix. This used to require `org/forgerock/openam/`, which made
     * every `store/*`, `config/*` and `components/*` id a blind spot -- batch B9 took a silent miss
     * on `store/actions/creators`, which is named-exports-only, and had to find it by hand. A bare
     * npm specifier simply has no file under src/main/js and falls out here.
     */
    const base = `${SRC_ROOT}/${dep}`;
    const path = [".js", ".jsm", ".jsx"].map((ext) => base + ext).find((p) => existsSync(p));
    if (!path) { return null; }
    let ast;
    try {
        ast = babel.parse(readFileSync(path, "utf8"), { sourceType: "module", plugins: ["jsx"] });
    } catch { return null; }
    const body = ast.program.body;
    const named = [];
    let hasDefault = false;
    for (const n of body) {
        if (n.type === "ExportDefaultDeclaration") { hasDefault = true; }
        if (n.type === "ExportNamedDeclaration") {
            for (const sp of n.specifiers || []) { named.push(sp.exported.name); }
            const d = n.declaration;
            if (d && d.id) { named.push(d.id.name); }
            for (const decl of (d && d.declarations) || []) {
                if (decl.id.type === "Identifier") { named.push(decl.id.name); }
            }
        }
    }
    if (hasDefault || named.length === 0) { return null; }
    return named;
};

/*
 * The transform slices source spans rather than re-printing an AST, so comments survive by
 * construction -- EXCEPT where a span is not carried across at all. Two such places exist: the
 * dependency ARRAY, whose import lines are rebuilt from the dep strings (so a `// jquery
 * dependencies` note inside it is dropped), and, until it was fixed, the gap between an arrow
 * factory's `=>` and its expression.
 *
 * Both were found by diffing comment multisets by hand, after the fact -- once in B4 (a 12-line
 * JSDoc block with an @example) and once in B6 (a dep-array note). Neither lint nor the build sees
 * this. So the tool now checks itself and names what it could not carry, turning a silent loss into
 * an instruction to re-site the comment.
 */
const commentBag = (text) => {
    let ast;
    try {
        ast = babel.parse(text, { sourceType: "unambiguous", plugins: ["jsx"], errorRecovery: true });
    } catch { return null; }
    return (ast.comments || []).map((c) => c.value.replace(/\s+/g, " ").trim()).filter(Boolean);
};

/*
 * REVIEW FIX. `commentBag` parses with errorRecovery, and returns null on hard failure -- and
 * `lostComments` then reported "nothing lost". Combined with the illegal-return bug above, the
 * tool could emit a file that does not parse at all and still print `OK ... LOSTC:none`. The
 * output is therefore re-parsed once, strictly, as a MODULE. This is the check that makes every
 * other self-check meaningful: a bag comparison over a file that never parsed proves nothing.
 */
const assertParsesAsModule = (text, file) => {
    try {
        babel.parse(text, { sourceType: "module", plugins: ["jsx"], errorRecovery: false });
    } catch (e) {
        throw new Error(`${file}: OUTPUT DOES NOT PARSE as an ES module -- ${e.message}`);
    }
};

const lostComments = (before, after) => {
    const pre = commentBag(before);
    const post = commentBag(after);
    if (!pre || !post) { return []; }
    const bag = new Map();
    for (const c of post) { bag.set(c, (bag.get(c) || 0) + 1); }
    const missing = [];
    for (const c of pre) {
        const n = bag.get(c) || 0;
        if (n === 0) { missing.push(c); } else { bag.set(c, n - 1); }
    }
    // the `global define` pragma is removed on purpose
    return missing.filter((m) => !/^globals?\s+define$/.test(m));
};

export const convert = (file) => {
    const src = readFileSync(file, "utf8");
    const ast = acorn.parse(src, { ecmaVersion: 9, sourceType: "script" });

    const stmts = ast.body.filter((n) =>
        n.type === "ExpressionStatement" &&
        n.expression.type === "CallExpression" &&
        n.expression.callee.type === "Identifier" &&
        n.expression.callee.name === "define");

    if (stmts.length !== 1) { throw new Error(`${file}: expected exactly 1 top-level define, found ${stmts.length}`); }

    const stmt = stmts[0];
    let args = stmt.expression.arguments;
    let namedId = null;
    if (args[0] && args[0].type === "Literal" && typeof args[0].value === "string") {
        namedId = args[0].value;
        args = args.slice(1);
    }

    /*
     * `/*global define* /` (without the space) is a linter pragma for a global that no longer
     * exists once the file is ESM, so it goes with the wrapper. Removed only when `define` is the
     * ONLY name the pragma declares -- a list like `define, require` is left alone, because
     * dropping the whole comment would silence a pragma that is still doing work.
     */
    const head = src.slice(0, stmt.start)
        .replace(/^[ \t]*\/\*\s*globals?\s+define\s*\*\/[ \t]*\r?\n(\r?\n)?/m, "");
    let tail = src.slice(stmt.end).replace(/^[ \t]*\n?/, "");

    // define({ literal })
    if (args.length === 1 && args[0].type === "ObjectExpression") {
        const out = `${head}export default ${src.slice(args[0].start, args[0].end)};\n${tail}`;
        // review fix: this path used to return before the self-checks, so LOSTC never ran on it
        assertParsesAsModule(out, file);
        return { text: out, imports: [], warnings: [], lost: lostComments(src, out), namedId,
            form: "define({lit})", hasExport: true };
    }

    const depsNode = args[0] && args[0].type === "ArrayExpression" ? args[0] : null;
    const factory = args.find((a) => a.type === "FunctionExpression" || a.type === "ArrowFunctionExpression");

    if (!factory) { throw new Error(`${file}: define with no factory -- hand work (see notes 1a)`); }

    const deps = depsNode ? depsNode.elements.map((e) => {
        if (e.type !== "Literal") { throw new Error(`${file}: non-literal dep id`); }
        return e.value;
    }) : [];
    const params = factory.params.map((p) => {
        if (p.type !== "Identifier") { throw new Error(`${file}: non-identifier factory param -- hand work`); }
        return p.name;
    });

    if (params.length > deps.length) { throw new Error(`${file}: ${params.length} params for ${deps.length} deps`); }
    const pseudo = deps.filter((d) => PSEUDO.has(d));
    if (pseudo.length) { throw new Error(`${file}: pseudo-dep(s) ${pseudo.join(",")} -- hand work`); }

    /*
     * A dependency becomes a NAMED import only if its factory parameter is actually referenced.
     * An unreferenced parameter means the module was depended on for its side effects -- a jQuery
     * plugin, an EventManager registration -- so it becomes `import "x";`. The edge is load-bearing
     * either way and must never be dropped; only the binding is noise.
     *
     * ESLint does not catch these. `no-unused-vars` runs with the default `args: "after-used"`,
     * which hides an unread parameter that PRECEDES a used one -- which is how three of them sat
     * unnoticed in common/components/table/InlineEditRow.js through the whole AMD era.
     *
     * The test counts Identifier nodes by name, so a shadowed inner binding reads as a use. That
     * errs towards keeping the named import, which is the safe direction.
     */
    const notAReference = new Set();
    walk(factory.body, (n) => {
        // `a.Foo` -- `Foo` is a property name, not a use of a binding called Foo
        if ((n.type === "MemberExpression" || n.type === "OptionalMemberExpression") && !n.computed) {
            notAReference.add(n.property);
        }
        /*
         * `{ Foo: 1 }`, `class { Foo () {} }` -- likewise.
         *
         * !n.shorthand IS LOAD-BEARING (review fix). For `{ Foo }` the parser sets key === value --
         * THE SAME NODE OBJECT -- so blacklisting the key here also blacklisted the only reference
         * to the binding, and the dep silently became `import "a/b/Foo";` plus an undefined `Foo`.
         * `no-undef` would have caught it, but only after the fact and only where lint runs.
         */
        if (KEYED.has(n.type) && !n.computed && !n.shorthand) { notAReference.add(n.key); }
    });
    const referenced = new Set();
    walk(factory.body, (n) => {
        if ((n.type === "Identifier" || n.type === "JSXIdentifier") && !notAReference.has(n)) {
            referenced.add(n.name);
        }
    });

    /*
     * max-len is [2, 120, 4] with no `ignoreStrings`, and AM's ids are long enough to blow it on
     * their own: a deep `common/models/schemaTransforms/...` import is ~152 characters. Wrap after
     * `from`, continuation indented four.
     */
    const warnings = [];
    const imports = deps.map((dep, i) => {
        if (i >= params.length || !referenced.has(params[i])) { return `import "${dep}";`; }
        const named = namedOnlyExports(dep);
        if (named) {
            warnings.push(`${params[i]} <- ${dep} has NO default export; named: ${named.join(", ")}`);
        }
        const line = `import ${params[i]} from "${dep}";`;
        return line.length <= MAX_LEN ? line : `import ${params[i]} from\n    "${dep}";`;
    });

    /*
     * Expression-bodied arrow factory -- `define([...], ($, _) => ...)`.
     *
     * Whether this needs the four-column dedent is decided by the indentation of the line the
     * expression ENDS on -- not by where it starts, which was the first two guesses and was wrong
     * both times.
     *
     *     }));            <- expression closes at column 0; its lines already sit where the ES body
     *                        wants them. Do NOT dedent.  (common/components/PartialBasedView.js)
     *
     *     })              <- expression closes at column 4, so every line of it is four columns
     *     );                 deeper than the ES body wants. DO dedent.
     *                        (common/components/TemplateBasedView.js, and
     *                         admin/views/realms/authorization/policies/EditPolicyView.js)
     *
     * The first version assumed the PartialBasedView shape always held; TemplateBasedView came out
     * four columns too deep. The second version tested for a newline between the `=>` and the body,
     * which fixed TemplateBasedView but not EditPolicyView -- that one opens on the SAME line as
     * `=>` (`…FormHelper) => AbstractView.extend({`) and still closes at column 4. Only ESLint
     * `indent` caught it, 15 errors deep into batch B8. The closing column is the property that
     * actually distinguishes the two.
     */
    if (factory.body.type !== "BlockStatement") {
        const arrow = src.lastIndexOf("=>", factory.body.start);
        const lineStart = src.lastIndexOf("\n", factory.body.end - 1) + 1;
        const closingColumn = /^[ \t]*/.exec(src.slice(lineStart, factory.body.end))[0].length;
        const spansLines = src.slice(factory.body.start, factory.body.end).includes("\n");
        let expr = src.slice(factory.body.start, factory.body.end);
        if (spansLines && closingColumn >= 4) {
            // fixed 4: the slice starts at the expression, so line 0 carries no indent to measure
            expr = dedent(expr, templateGuards(factory.body, src, factory.body.start), 4);
        }

        /*
         * Anything between the `=>` and the expression is a COMMENT, and slicing from
         * factory.body.start throws it away. Two files in batch B4 lost real JSDoc that way --
         * bindSavePromiseToElement.js lost a 12-line block including its @example -- and it was
         * caught by reading the diff, not by any check. Carry it across, dedented like the
         * expression it documents.
         */
        const between = arrow === -1 ? "" : src.slice(arrow + 2, factory.body.start);
        let lead = "";
        if (between.includes("/*") || between.includes("//")) {
            const block = between.replace(/^[ \t]*\r?\n/, "").replace(/\s+$/, "").split("\n");
            // strip the block's OWN common indent, not a fixed four -- three files in admin/utils
            // sit at a stray one-space base indent, and a fixed dedent leaves them at one.
            const pad = Math.min(...block.filter((l) => l.trim())
                .map((l) => l.length - l.trimStart().length));
            lead = `${block.map((l) => l.slice(pad)).join("\n")}\n`;
        }

        /*
         * `export default function name () {}` and `export default class X {}` are DECLARATIONS,
         * so they take no trailing `;` -- the same rule the block path applies, which this path was
         * missing (admin/utils/deprecatedWarning.js, `no-extra-semi`). An arrow or any other
         * expression still needs one.
         */
        const semi = DECLARATION_EXPR.has(factory.body.type) ? "" : ";";

        const out = [head];
        if (imports.length) { out.push(`${imports.join("\n")}\n\n`); }
        out.push(`${lead}export default ${expr}${semi}\n`);
        if (tail.trim()) { out.push(`\n${tail.replace(/^\n+/, "")}`); }
        const text = out.join("");
        assertParsesAsModule(text, file);
        return { text, imports, warnings, lost: lostComments(src, text), namedId,
            form: "define([d],expr-arrow)", hasExport: true };
    }

    // body slice, with the single top-level `return` rewritten in place
    const bodyStart = factory.body.start + 1;
    const bodyEnd = factory.body.end - 1;
    const returns = factory.body.body.filter((n) => n.type === "ReturnStatement");
    if (returns.length > 1) { throw new Error(`${file}: ${returns.length} top-level returns`); }

    /*
     * REVIEW FIX. The filter above only sees DIRECT children of the factory block, so a `return`
     * inside a top-level block -- `if (!C) { return null; }`, a very ordinary AMD guard clause --
     * was invisible to it. The wrapper strip then left that `return` at module top level, which is
     * "Illegal return statement": the tool emitted a file that cannot parse, and reported OK.
     * Refuse instead. A guard clause has to become an explicit early value by hand; there is no
     * mechanical rewrite of it that is obviously correct.
     */
    const nested = [];
    walk(factory.body, (n) => {
        if (n.type === "ReturnStatement" && !returns.includes(n)) { nested.push(n); }
    }, FUNCTION_TYPES);
    if (nested.length > 0) {
        throw new Error(
            `${file}: \`return\` inside a top-level block (line ` +
            `${src.slice(0, nested[0].start).split("\n").length}). Stripping the wrapper would ` +
            "leave it at module top level -- an illegal return. Rewrite it by hand."
        );
    }

    let body = src.slice(bodyStart, bodyEnd);
    if (returns.length === 1) {
        const r = returns[0];
        if (!r.argument) { throw new Error(`${file}: bare \`return;\` at top level`); }

        /*
         * `export default class X {}` and `export default function f () {}` are DECLARATIONS, not
         * expression statements, so the `;` that terminated the old `return` becomes a stray
         * EmptyStatement -- `no-extra-semi`. Drop it. Every other argument shape keeps its `;`,
         * because `export default <expression>;` does need one. Five of B2's fourteen files hit
         * this, so it is the common case in this tree, not an edge.
         *
         * Done BEFORE the `return` rewrite so the offsets below are still the parser's.
         */
        if (DECLARATION_EXPR.has(r.argument.type) && src[r.end - 1] === ";") {
            const semi = r.end - 1 - bodyStart;
            body = `${body.slice(0, semi)}${body.slice(semi + 1)}`;
        }

        const rel = r.start - bodyStart;
        body = `${body.slice(0, rel)}export default${body.slice(rel + "return".length)}`;
    }

    body = dedent(body, templateGuards(factory.body, src, bodyStart))
        .replace(/^\n+/, "").replace(/\s+$/, "");

    const parts = [head];
    if (imports.length) { parts.push(`${imports.join("\n")}\n\n`); }
    parts.push(`${body}\n`);
    if (tail.trim()) { parts.push(`\n${tail.replace(/^\n+/, "")}`); }

    const text = parts.join("");
    assertParsesAsModule(text, file);
    return {
        text,
        imports,
        warnings,
        lost: lostComments(src, text),
        namedId,
        form: depsNode ? "define([d],fn)" : "define(fn)",
        hasExport: returns.length === 1
    };
};

const files = process.argv.slice(2);
const write = process.env.WRITE === "1";
for (const file of files) {
    try {
        const r = convert(file);
        if (write) { writeFileSync(file, r.text); }
        console.log(`OK   ${file}  ${r.form}  imports=${r.imports.length}  export=${r.hasExport !== false}${r.namedId ? `  namedId=${r.namedId}` : ""}`);
        for (const w of r.warnings || []) { console.log(`WARN   ${w}`); }
        for (const c of r.lost || []) {
            console.log(`LOSTC  comment not carried across, re-site it: ${c.slice(0, 120)}`);
        }
    } catch (e) {
        console.log(`FAIL ${file}  ${e.message}`);
    }
}
