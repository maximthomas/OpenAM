/*
 * TASK 5.2. Sets the three globals ../libs/backgrid-paginator-0.3.5-custom.min.js reads on its
 * accidental second factory call. See ./backgrid-paginator.js for why that call happens.
 *
 * THIS IS A SEPARATE FILE ON PURPOSE, and the reason is easy to get wrong: ES module `import`
 * declarations are HOISTED. Writing the assignments and then `import "../libs/backgrid-..."`
 * below them in one file does NOT work -- the library would still evaluate first, and the globals
 * would be set too late to matter. Only a module boundary orders them, because a module is fully
 * evaluated before the importer that depends on it.
 *
 * TASK 8.3: `_` HERE IS underscore, NOT lodash, AND SWAPPING IT BACK BREAKS THE PAGINATOR.
 * Until 8.3 this file imported `../libs/lodash-3.10.1-min.js` by literal path, which was invisible
 * to the alias table; 8.3 deleted that file, so the import had to change and the only question was
 * to WHAT. The answer is fixed by the library, not by preference. Its prologue is:
 *
 *     !function(a,b){"object"==typeof exports&&(module.exports=b(require("underscore"),...)),
 *                    "function"==typeof define&&define.amd?define([...],b):b(a._,a.Backbone,a.Backgrid)}
 *
 * Note the COMMA after the `&&(...)`: the CommonJS assignment is a statement, not an early return,
 * so the ternary after it still evaluates. In a Rollup bundle there is no `define.amd`, so the else
 * branch fires and the factory runs a SECOND time -- on these globals. Both calls write
 * `Extension.Paginator` onto the same Backgrid object, so THE SECOND CALL WINS, which makes the
 * library the app actually uses the one built from `window._`.
 *
 * That library is written against underscore. Its `makeHandles` is
 * `a.each([...], function (name) { ... new this.pageHandle(e) ... }, this)` -- a thisArg. underscore
 * still honours a third argument (`each.length === 3`); lodash 4 dropped it (`each.length === 2`)
 * and passes nothing, so `this` is undefined under the factory's own "use strict" and every
 * paginated grid throws `Cannot read properties of undefined (reading 'pageHandle')` on render.
 * ThemeablePaginator does not override makeHandles, so that is ScriptsView, PoliciesView,
 * PolicySetsView, ResourceTypesView, ListHistory and the rest of the admin grids.
 *
 * This was not a problem before 8.3 only because `window._` was lodash 3.10.1, which DID support
 * thisArg. The vendored file is gone; underscore is the library that matches what the paginator
 * asks for by name, so it is what it gets.
 */
import _ from "underscore";
import Backbone from "./backbone.js";
import Backgrid from "backgrid";

window._ = _;
window.Backbone = Backbone;
window.Backgrid = Backgrid;

export default Backgrid;
