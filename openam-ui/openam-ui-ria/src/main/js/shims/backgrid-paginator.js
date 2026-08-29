/*
 * TASK 5.2. THE VENDORED FORK CALLS ITS FACTORY TWICE UNDER COMMONJS. Its prologue uses a COMMA
 * where a stock UMD uses `else if`:
 *
 *     !function(a,b){
 *       "object"==typeof exports&&(module.exports=b(require("underscore"),require("backbone"),
 *                                                   require("backgrid"),require("backbone.paginator"))),
 *       "function"==typeof define&&define.amd ? define([...],b)
 *                                             : b(a._,a.Backbone,a.Backgrid)
 *     }(this, function(a,b,c){ "use strict"; var d=c.Extension.PageHandle=b.View.extend({...
 *
 * Under CommonJS BOTH statements run: `module.exports = ...` succeeds, then `define` is undefined
 * so the else branch calls the factory a SECOND time with `a._`, `a.Backbone`, `a.Backgrid`,
 * where `a` is top-level `this` (which @rollup/plugin-commonjs rewrites to commonjsGlobal).
 *
 * MEASURED, NOT INFERRED. Built through this config and evaluated:
 *   without the globals -> TypeError: Cannot read properties of undefined (reading 'Extension')
 *   with the globals    -> gets past it (fails later only on `document`, i.e. no DOM in node)
 * Today the AMD branch is taken and the else never runs, so this is latent rather than broken.
 *
 * This is a property of the LOCAL FORK, not of upstream backgrid-paginator. Three fixes were on
 * the table; the change owner chose this one. Patching the comma would break byte-parity and
 * invalidate the md5 pinned in ../libs/README.md, reopening the fork question that
 * NOTES-libs-retire.md section 12.3 still records as open; aliasing to npm's
 * backgrid-paginator@0.3.5 would swap in the Cloudflare fork, a different lineage and a
 * behaviour decision. Setting the globals keeps the vendored bytes exact.
 *
 * ./backgrid-globals.js must be a separate module for the import-hoisting reason recorded there.
 */
import Backgrid from "./backgrid-globals.js";
import "../libs/backgrid-paginator-0.3.5-custom.min.js";

export default Backgrid;
