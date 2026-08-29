/*
 * TASK 5.2. THE ORDERING CONSTRAINT NO SHIM EVER ENCODED. `popoverclickaway` is a bare `paths`
 * row at main.js:65 with NO shim entry at all, yet its last statement reads a Bootstrap-supplied
 * value at evaluation time:
 *
 *     $.fn.popoverclickaway.defaults = $.extend({}, $.fn.popover.defaults, { trigger: "manual" });
 *     ...
 *     }(window.jQuery);
 *
 * `$.fn.popover` is registered by Bootstrap. Under AMD this worked by luck: all three of its
 * consumers reach it after AbstractView has already pulled Bootstrap in. Nothing declared it, so
 * nothing preserved it, and an import graph built per-module would have reordered it silently.
 *
 * The file itself is THIS PROJECT'S OWN SOURCE, not a third-party library -- ../libs/README.md
 * records it as such and .gitattributes already exempts it from the vendored `-text` rule. It
 * sits under libs/ for historical reasons only; moving it into src/main/js proper is worth doing
 * when it is converted, and is not this task's.
 */
import $ from "./bootstrap.js";
import "../libs/popover-clickaway.js";

export default $;
