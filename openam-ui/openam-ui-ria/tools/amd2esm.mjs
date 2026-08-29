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
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";

// resolves acorn from openam-ui-ria/node_modules, wherever the checkout lives
const require = createRequire(import.meta.url);
const acorn = require("acorn");

const PSEUDO = new Set(["require", "exports", "module"]);

const walk = (node, fn) => {
    if (!node || typeof node.type !== "string") { return; }
    fn(node);
    for (const key of Object.keys(node)) {
        if (key === "type" || key === "start" || key === "end" || key === "loc") { continue; }
        const value = node[key];
        if (Array.isArray(value)) { value.forEach((child) => walk(child, fn)); }
        else if (value && typeof value.type === "string") { walk(value, fn); }
    }
};

const dedent = (text, protectedRanges, offset) => text.split("\n").map((line, index, lines) => {
    // absolute offset of this line's start
    let abs = offset;
    for (let i = 0; i < index; i++) { abs += lines[i].length + 1; }
    const guarded = protectedRanges.some(([s, e]) => abs > s && abs < e);
    if (guarded) { return line; }
    return line.startsWith("    ") ? line.slice(4) : line.replace(/^\s+/, "");
}).join("\n");

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

    const head = src.slice(0, stmt.start);
    let tail = src.slice(stmt.end).replace(/^[ \t]*\n?/, "");

    // define({ literal })
    if (args.length === 1 && args[0].type === "ObjectExpression") {
        const out = `${head}export default ${src.slice(args[0].start, args[0].end)};\n${tail}`;
        return { text: out, imports: [], namedId, form: "define({lit})" };
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

    const imports = deps.map((dep, i) =>
        (i < params.length ? `import ${params[i]} from "${dep}";` : `import "${dep}";`));

    /*
     * Expression-bodied arrow factory -- `define([...], ($, _) => ({ ... }))`. The returned
     * expression's own lines already sit at the indent the ES body wants (the `=> ({` opener is
     * itself at column 0), so this branch must NOT dedent. Block bodies below must.
     */
    if (factory.body.type !== "BlockStatement") {
        const expr = src.slice(factory.body.start, factory.body.end);
        const out = [head];
        if (imports.length) { out.push(`${imports.join("\n")}\n\n`); }
        out.push(`export default ${expr};\n`);
        if (tail.trim()) { out.push(`\n${tail.replace(/^\n+/, "")}`); }
        return { text: out.join(""), imports, namedId, form: "define([d],expr-arrow)", hasExport: true };
    }

    // body slice, with the single top-level `return` rewritten in place
    const bodyStart = factory.body.start + 1;
    const bodyEnd = factory.body.end - 1;
    const returns = factory.body.body.filter((n) => n.type === "ReturnStatement");
    if (returns.length > 1) { throw new Error(`${file}: ${returns.length} top-level returns`); }

    let body = src.slice(bodyStart, bodyEnd);
    if (returns.length === 1) {
        const r = returns[0];
        if (!r.argument) { throw new Error(`${file}: bare \`return;\` at top level`); }
        const rel = r.start - bodyStart;
        body = `${body.slice(0, rel)}export default${body.slice(rel + "return".length)}`;
    }

    /*
     * Never dedent a line that begins inside the STRING part of a multi-line template literal --
     * there the leading whitespace is content, and removing it changes the value.
     *
     * Guard the quasis, NOT the whole TemplateLiteral. The interior of a `${...}` substitution is
     * an ordinary JavaScript expression whose indentation is formatting like any other, so it must
     * be dedented with the rest of the body. Guarding the literal wholesale leaves those lines
     * four columns too deep relative to their new anchor -- which is exactly what happened to
     * common/util/URLHelper.js in batch B1 and had to be fixed by hand.
     */
    const guards = [];
    walk(factory.body, (n) => {
        if (n.type !== "TemplateLiteral") { return; }
        for (const quasi of n.quasis) {
            if (src.slice(quasi.start, quasi.end).includes("\n")) {
                guards.push([quasi.start - bodyStart, quasi.end - bodyStart]);
            }
        }
    });

    body = dedent(body, guards, 0).replace(/^\n+/, "").replace(/\s+$/, "");

    const parts = [head];
    if (imports.length) { parts.push(`${imports.join("\n")}\n\n`); }
    parts.push(`${body}\n`);
    if (tail.trim()) { parts.push(`\n${tail.replace(/^\n+/, "")}`); }

    return {
        text: parts.join(""),
        imports,
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
    } catch (e) {
        console.log(`FAIL ${file}  ${e.message}`);
    }
}
