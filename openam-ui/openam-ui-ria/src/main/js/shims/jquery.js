/*
 * TASK 5.2. jQuery's UMD sets `window.jQuery` / `window.$` ONLY on its browser/AMD branch.
 *
 *     "object"==typeof module&&"object"==typeof module.exports
 *       ? module.exports = e.document ? t(e,!0) : ...     // <- CommonJS: t(e, TRUE)
 *       : t(e)                                            // <- browser:  t(e)
 *     ...
 *     "undefined"==typeof e && (ie.jQuery = ie.$ = ce)     // e === noGlobal
 *
 * The CommonJS branch passes `noGlobal = true`, so the globals are NOT assigned. An ES module
 * build takes that branch (@rollup/plugin-commonjs supplies `module`/`exports`), which is why
 * nothing in AM ever had to set these and why everything that reads them breaks at once.
 *
 * Nine bound ids read the global AT EVALUATION TIME, not lazily: `bootstrap` throws
 * "Bootstrap's JavaScript requires jQuery" loudly, and `i18next` fails SILENTLY -- it falls back
 * to its own internal extend/each/ajax and never registers `$.t` or `$.fn.i18n`.
 *
 * main-authorize.js:70-71 already does exactly this assignment, described there as "helpers for
 * the code that hasn't been properly migrated". Under ESM it stops being a helper and becomes
 * load-bearing; main.js and main-device.js have no equivalent line.
 *
 * Imports the concrete path, NOT the bare id: `jquery` is aliased to THIS FILE, so `import from
 * "jquery"` here would resolve back to itself.
 */
import $ from "jquery/dist/jquery.js";

window.jQuery = $;
window.$ = $;

export default $;
