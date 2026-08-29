/*
 * TASK 5.2. Twelve plugin IIFEs, each shaped `+function ($) { ... }(jQuery)`, reading the FREE
 * global. The file opens by throwing if it is absent:
 *
 *     if (typeof jQuery === 'undefined') { throw new Error("Bootstrap's JavaScript requires jQuery") }
 *
 * So this is the loud member of the ./jquery.js group -- it fails immediately and unmistakably
 * rather than silently. Shim was `deps: ["jquery"]`, no exports.
 *
 * THE SUBPATH IS DELIBERATE. Bare "bootstrap" resolves to bootstrap/dist/js/npm.js, a DIFFERENT
 * file: twelve separate requires of the individual plugin files. dist/js/bootstrap.js is the one
 * concatenated build AM has always shipped (NPM_LIBRARY_FILES stages exactly this file into
 * libs/bootstrap-3.3.5-min.js). Both read the same free global and both would work; this one is
 * the bytes AM ships, so parity costs nothing here and is worth having.
 */
import $ from "./jquery.js";
import "bootstrap/dist/js/bootstrap.js";

/*
 * Re-exported so that ./bootstrap-tabdrop.js and ./popover-clickaway.js -- which need Bootstrap
 * loaded, not merely jQuery -- can import ONE module and still get `$` back. Consumers of the
 * `bootstrap` id itself ignore the value, exactly as they did under AMD, where the shim declared
 * `deps: ["jquery"]` and no `exports`.
 */
export default $;
