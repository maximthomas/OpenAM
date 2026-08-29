/*
 * TASK 5.2. Vendored; all four plausible npm names 404 (D20). Ends `})(jQuery);` -- free global
 * at evaluation. `exports: "doTimeout"` was dead in the same way autosizeInput's was: the file
 * sets `$.doTimeout`, never `window.doTimeout`. Both consumers use `$.doTimeout`.
 */
import $ from "./jquery.js";
import "../libs/jquery.ba-dotimeout-1.0-min.js";

export default $;
