/*
 * TASK 5.2. Sets the three globals ../libs/backgrid-paginator-0.3.5-custom.min.js reads on its
 * accidental second factory call. See ./backgrid-paginator.js for why that call happens.
 *
 * THIS IS A SEPARATE FILE ON PURPOSE, and the reason is easy to get wrong: ES module `import`
 * declarations are HOISTED. Writing the assignments and then `import "../libs/backgrid-..."`
 * below them in one file does NOT work -- the library would still evaluate first, and the globals
 * would be set too late to matter. Only a module boundary orders them, because a module is fully
 * evaluated before the importer that depends on it.
 */
import _ from "../libs/lodash-3.10.1-min.js";
import Backbone from "./backbone.js";
import Backgrid from "backgrid";

window._ = _;
window.Backbone = Backbone;
window.Backgrid = Backgrid;

export default Backgrid;
