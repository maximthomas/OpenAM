/*
 * TASK 5.2. npm package name differs from the AMD id: `jquery-sortable`, not `sortable`. Ends
 * `}(jQuery, window, 'sortable');` -- free global at evaluation -- so it needs the ordering as
 * well as the rename. Shim was `deps: ["jquery"]`, no exports.
 *
 * Its two consumers are EditChainView.js and ManageRulesView.js; task 1.15 added the chain
 * coverage that would notice this breaking, and ManageRulesView remains uncovered.
 */
import $ from "./jquery.js";
import "jquery-sortable/source/js/jquery-sortable.js";

export default $;
