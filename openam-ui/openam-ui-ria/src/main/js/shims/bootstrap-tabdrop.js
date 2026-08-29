/*
 * TASK 5.2. Vendored: the npm package of this name is ispot-tv's fork with no 1.0 release, a
 * different lineage (D20). Ends `}(window.jQuery);` and registers `$.fn.tabdrop`.
 *
 * Shim was `deps: ["jquery", "bootstrap"]` and BOTH halves are real -- it is a Bootstrap tab
 * plugin -- so ./bootstrap.js is imported here rather than ./jquery.js, which it already pulls in.
 * Nine declarers, the largest consumer count of any vendored file.
 */
import $ from "./bootstrap.js";
import "../libs/bootstrap-tabdrop-1.0.js";

export default $;
