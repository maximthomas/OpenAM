/*
 * TASK 5.2. Two problems, like i18next but neither silent.
 *
 * 1. THE SPECIFIER. `clockpicker` publishes NO `main` and NO `index.js` -- its package.json has
 *    no entry-point field at all -- so the bare name does not resolve (verified: MODULE_NOT_FOUND).
 *    The subpath below is the file NPM_LIBRARY_FILES already stages.
 * 2. THE ORDERING. It captures jQuery into its IIFE at evaluation and registers `$.fn.clockpicker`.
 *
 * `exports: "clockPicker"` was dead: the file sets `$.fn.clockpicker`, never a window property.
 */
import $ from "./jquery.js";
import "clockpicker/dist/bootstrap-clockpicker.min.js";

export default $;
