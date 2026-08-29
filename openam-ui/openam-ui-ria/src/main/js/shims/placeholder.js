/*
 * TASK 5.2. jquery-placeholder reads the FREE `jQuery` global at evaluation and registers
 * `$.fn.placeholder`. Measured: without this shim the bundle throws "jQuery is not defined" at
 * import, so it belongs to the ./jquery.js group even though it is not in any require.config
 * paths block and therefore not in NOTES-shims.md's table.
 *
 * `placeholder` is imported by ui-commons common/LoginView.js and by ui-user's
 * AbstractUserProfileTab.js and UserProfileKBATab.js. See the alias block in vite.config.js for
 * why the id had to be restored at all, and why 2.0.7 rather than the 2.0.8 AM used to ship.
 */
import $ from "./jquery.js";
import "jquery-placeholder/jquery.placeholder.js";

export default $;
