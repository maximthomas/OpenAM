/*
 * TASK 5.2. Vendored, no npm publication under any name (D20). A TypeScript-namespace IIFE that
 * ends `}(jQuery)})(Plugins||(Plugins={}))` -- the free global, read at evaluation -- and then
 * registers a document-ready hook, `t(function(){ t("input[data-"+i+"]").autosizeInput() })`,
 * which also runs through the captured jQuery.
 *
 * The AMD shim said `exports: "autosizeInput"`, which was ALREADY DEAD: the file sets
 * `Plugins.AutosizeInput` and `$.fn.autosizeInput`, never `window.autosizeInput`, so the id
 * resolved to undefined. Its one consumer reaches it through `$`, which is why nobody noticed.
 * The shim therefore hands back jQuery rather than reproducing an export that never existed.
 */
import $ from "./jquery.js";
import "../libs/jquery.autosize.input.min.js";

export default $;
