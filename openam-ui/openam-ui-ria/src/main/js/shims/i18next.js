/*
 * TASK 5.2. Two separate problems, and the second is the dangerous one.
 *
 * 1. THE SPECIFIER. Bare "i18next" resolves to i18next/index.js -> lib/i18next.js, which is the
 *    NODE build: it requires 'fs', 'cookies' and 'filesync'. Measured, not assumed -- building
 *    the bare id SUCCEEDS and produces a 636 KB bundle that drags in express, keygrip, router,
 *    serve-static and tsscmp, with fs/http/crypto/net/path/buffer "externalized for browser
 *    compatibility". Exit code 0, completely broken at runtime. The browser build is in the same
 *    tarball at lib/dep/i18next.min.js (32 KB), which is what NPM_LIBRARY_FILES already stages.
 *
 * 2. THE ORDERING. The browser build reads jQuery from a global at evaluation:
 *
 *        A = this, B = A.jQuery || A.Zepto
 *        ... extend: B ? B.extend : a, each: B ? B.each : b, ajax: B ? B.ajax : ...
 *
 *    If B is undefined it does NOT throw -- it falls back to its own internal implementations and
 *    simply never registers `$.t` or `$.fn.i18n`. This is the SILENT failure in the ./jquery.js
 *    group, and the reason this shim exists rather than a plain alias to the subpath.
 *
 * The `exports: "i18n"` in the AMD shim was one of only two load-bearing exports fields in the
 * whole block, but it is not needed here: the file ends
 *     "undefined"!=typeof module&&module.exports ? module.exports=C : (B&&(B.i18n=...))
 * so under CommonJS it assigns module.exports and the default import below IS the i18n object.
 *
 * The shim also declared `deps: ["jquery","handlebars"]`. The handlebars half is FICTION:
 * i18next.min.js contains zero occurrences of "Handlebars" or "handlebars", in all three entry
 * points. Not reproduced here.
 */
import "./jquery.js";
import i18n from "i18next/lib/dep/i18next.min.js";

export default i18n;
