/*
 * TASK 5.2. The vendored jsoneditor fork is a PLAIN IIFE -- no CommonJS branch, no AMD branch.
 * It ends:
 *
 *     ... window.JSONEditor = g }();
 *
 * so it has no ES export of any kind and importing it yields nothing. `exports: "JSONEditor"` was
 * the other genuinely load-bearing exports field in the AMD shim (the file really does have no
 * define() and really does set a window property), and this shim is what replaces it.
 *
 * It needs no jQuery ordering: the file installs a $.fn.jsoneditor bridge but reads jQuery
 * lazily, inside that plugin function, not at evaluation.
 */
import "../libs/jsoneditor-0.7.23-custom.js";

export default window.JSONEditor;
