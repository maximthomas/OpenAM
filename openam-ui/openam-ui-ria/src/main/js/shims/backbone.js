/*
 * TASK 5.2. Backbone 1.1.2's UMD, quoted in full:
 *
 *     if (typeof define === "function" && define.amd) {
 *       define(["underscore","jquery","exports"], function(i,r,s){ t.Backbone = e(t,s,i,r) })
 *     } else if (typeof exports !== "undefined") {
 *       var i = require("underscore"); e(t, exports, i)        // <- THREE arguments
 *     } else {
 *       t.Backbone = e(t, {}, t._, t.jQuery||t.Zepto||t.ender||t.$)
 *     }
 *     })(this, function(t, e, i, r){ ... e.$ = r; ... })
 *
 * The AMD branch passes FOUR arguments and jquery is the fourth. The CommonJS branch passes
 * THREE, so `r` is undefined and `Backbone.$ = undefined`. Every Backbone View in AM and in
 * commons needs `Backbone.$` for `this.$el`.
 *
 * Setting `window.jQuery` does NOT help here -- unlike the nine ids in ./jquery.js, this branch
 * never reads a global. It needs an assignment AFTER the import, which no import edge can
 * express. This is the one row where the ESM shape is strictly worse than the AMD one, and it
 * is the second most-imported id in the tree (51 declarers: 43 in src/main/js, 8 in commons).
 *
 * backgrid, backgrid-filter, backgrid-selectall, backgrid.paginator, backbone.paginator and
 * backbone-relational all inherit this transitively.
 *
 * Imports the concrete path for the same reason ./jquery.js does.
 */
import $ from "./jquery.js";
import Backbone from "backbone/backbone.js";

Backbone.$ = $;

export default Backbone;

/*
 * TASK 5.7. `common/components/SelectComponent.jsm:20` and `common/components/TemplateComponent
 * .jsm:18` -- both task 5.1 output -- do `import { View } from "backbone"`. Same defect as the
 * i18next shim above and found the same way, by a verification build. `View` is the only name any
 * consumer takes; a bare re-export is enough, and `Backbone.View` is fixed by the time this module
 * finishes evaluating.
 */
export const View = Backbone.View;
