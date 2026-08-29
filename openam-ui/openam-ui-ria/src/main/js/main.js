/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Portions copyright 2011-2016 ForgeRock AS.
 * Portions copyright 2025 3A Systems LLC.
 */

require.config({
    map: {
        "*" : {
            "Footer"            : "org/forgerock/openam/ui/common/components/Footer",
            "ThemeManager"      : "org/forgerock/openam/ui/common/util/ThemeManager",
            "LoginView"         : "org/forgerock/openam/ui/user/login/RESTLoginView",
            "UserProfileView"   : "org/forgerock/commons/ui/user/profile/UserProfileView",
            "ForgotUsernameView": "org/forgerock/openam/ui/user/anonymousProcess/ForgotUsernameView",
            "PasswordResetView" : "org/forgerock/openam/ui/user/anonymousProcess/PasswordResetView",
            "LoginDialog"       : "org/forgerock/openam/ui/user/login/RESTLoginDialog",
            "NavigationFilter"  : "org/forgerock/openam/ui/common/components/navigation/filters/RouteNavGroupFilter",
            "Router"            : "org/forgerock/commons/ui/common/main/Router",
            "RegisterView"      : "org/forgerock/openam/ui/user/anonymousProcess/SelfRegistrationView",
            "KBADelegate"       : "org/forgerock/openam/ui/user/services/KBADelegate",
            // TODO: Remove this when there are no longer any references to the "underscore" dependency
            "underscore"        : "lodash"
        }
    },
    /*
     * TASK 5.2 -- SUPERSEDED BY vite.config.js, AND DELIBERATELY STILL HERE.
     *
     * Every id below now has a `resolve.alias` entry in vite.config.js (the block headed
     * "5.2 -- THE RUNTIME LIBRARY BINDINGS"), so the ES module build resolves it without this
     * config. This block is NOT deleted because the tree is still AMD: RequireJS is what loads
     * `main` today, and removing these paths breaks the running UI for no gain. TASK 5.4 deletes
     * the whole require.config call when it converts the 203 define() modules and settles how the
     * three entry points are loaded.
     *
     * Reading the two together: the ids here map to files under libs/; the alias entries map the
     * SAME ids to npm packages, to shim modules in src/main/js/shims/, or to the vendored files
     * under src/main/js/libs/. NOTES-shims.md has the per-library table.
     *
     * Nine ids are not npm package names and stay bound by alias rather than being renamed at
     * their call sites, because the commons packages' published esm/ trees import them by these
     * same AMD ids and AM cannot edit those files.
     *
     * "text" is the one id with no alias and no successor: requirejs-text is an AMD loader plugin
     * that cannot be imported at all under ESM. TASK 5.5 owns its 8 `text!` call sites.
     */
    paths: {
        "autosizeInput": "libs/jquery.autosize.input.min",

        "backbone"           : "libs/backbone-1.1.2-min",
        "backbone.paginator" : "libs/backbone.paginator.min-2.0.2-min",
        "backbone-relational": "libs/backbone-relational-0.9.0-min",

        "backgrid"          : "libs/backgrid.min-0.3.5-min",
        "backgrid-filter"   : "libs/backgrid-filter.min-0.3.7-min",
        "backgrid.paginator": "libs/backgrid-paginator-0.3.5-custom.min",
        "backgrid-selectall": "libs/backgrid-select-all-0.3.5-min",

        "bootstrap"               : "libs/bootstrap-3.3.5-custom",
        "bootstrap-datetimepicker": "libs/bootstrap-datetimepicker-4.14.30-min",
        "bootstrap-dialog"        : "libs/bootstrap-dialog-1.34.4-min",
        "bootstrap-tabdrop"       : "libs/bootstrap-tabdrop-1.0",

        "classnames"       : "libs/classnames-2.2.5",
        "clockPicker"      : "libs/bootstrap-clockpicker-0.0.7-min",
        "doTimeout"        : "libs/jquery.ba-dotimeout-1.0-min",
        "form2js"          : "libs/form2js-2.0-769718a",
        "handlebars"       : "libs/handlebars-4.7.7",
        "i18next"          : "libs/i18next-1.7.3-min",
        "jquery"           : "libs/jquery-3.7.1-min",
        "js2form"          : "libs/js2form-2.0-769718a",
        "jsonEditor"       : "libs/jsoneditor-0.7.23-custom",
        "lodash"           : "libs/lodash-3.10.1-min",
        "microplugin"      : "libs/microplugin-0.0.3",
        "moment"           : "libs/moment-2.28.0-min",
        "popoverclickaway" : "libs/popover-clickaway",
        "qrcode"           : "libs/qrcode-1.4.4-min",
        "react-bootstrap"  : "libs/react-bootstrap-0.30.1-min",
        "react-dom"        : "libs/react-dom-15.2.1-min",
        "react"            : "libs/react-15.2.1-min",
        "react-input-autosize": "libs/react-input-autosize-1.1.0-min",
        "react-select"     : "libs/react-select-1.0.0-rc.2-min",
        "redux"            : "libs/redux-3.5.2-min",
        "selectize"        : "libs/selectize-non-standalone-0.12.1-min",
        "sifter"           : "libs/sifter-0.4.1-min",
        "sortable"         : "libs/jquery-sortable-0.9.13",
        "spin"             : "libs/spin-2.0.1-min",
        "text"             : "libs/text-2.0.15",
        "xdate"            : "libs/xdate-0.8-min"
    },
    /*
     * TASK 5.2 -- WHAT REPLACED THIS, ENTRY BY ENTRY.
     *
     * `deps` was load order. Most of it is now carried by the import graph for free, because each
     * library's own CommonJS branch require()s what the shim declared -- backbone.paginator,
     * backbone-relational, backgrid, backgrid-filter, backgrid-selectall, selectize and
     * bootstrap-datetimepicker are all in that class. What the graph CANNOT carry is a dependency
     * passed through a GLOBAL, because jQuery's CommonJS branch never assigns window.jQuery.
     * Those live in src/main/js/shims/, one file per id, aliased in front of it in
     * vite.config.js: jquery, backbone, bootstrap, i18next, autosizeInput, doTimeout,
     * bootstrap-tabdrop, popoverclickaway, sortable, clockPicker, jsonEditor, backgrid.paginator.
     *
     * `exports` mostly replaced nothing, because it was already dead. Measured from the bytes:
     * nine of the fourteen exports fields have no effect TODAY (RequireJS ignores `exports` when
     * the file calls define(), which backbone, backgrid, form2js, js2form, lodash, moment, qrcode,
     * spin and xdate all do), and three more resolve to undefined because the named global is
     * never set (clockPicker sets $.fn.clockpicker, doTimeout sets $.doTimeout, autosizeInput
     * sets $.fn.autosizeInput). Only two were load-bearing -- i18next -> i18n and
     * jsonEditor -> JSONEditor -- and both are handled by their shim.
     *
     * Two `deps` entries here are fiction and were not reproduced: selectize's
     * ["jquery","sifter","microplugin"] duplicates its own UMD's requires, and the "handlebars"
     * half of i18next's deps is wrong outright -- i18next.min.js contains zero occurrences of
     * Handlebars.
     *
     * The `react-input-autosize` and `react-select` entries ARE superseded, but by nothing --
     * TASK 5.3 settled them and the successor is an absence. Both are real npm package names, so
     * the ES module build resolves each bare specifier to its own package `main` (lib/Select.js,
     * lib/AutosizeInput.js), which requires react, react-dom, react-input-autosize and classnames
     * BY NAME and reads no globals. Adding an alias for either would be the bug, not the fix, so
     * vite.config.js has none and assertReactSelectNeedsNoGlobals fails the build if one appears.
     * The two `shim` entries below and the reactAutosizeInputDep / reactSelectDep modules are the
     * AMD half of the same binding and are still load-bearing today; they go with this block.
     *
     * Deleted by 5.4 with the rest of require.config, not here.
     */
    shim: {
        "autosizeInput": {
            deps: ["jquery"],
            exports: "autosizeInput"
        },
        "backbone": {
            deps: ["lodash"],
            exports: "Backbone"
        },
        "backbone.paginator": {
            deps: ["backbone"]
        },
        "backbone-relational": {
            deps: ["backbone"]
        },

        "backgrid": {
            deps: ["jquery", "lodash", "backbone"],
            exports: "Backgrid"
        },
        "backgrid-filter": {
            deps: ["backgrid"]
        },
        "backgrid.paginator": {
            deps: ["backgrid", "backbone.paginator"]
        },
        "backgrid-selectall": {
            deps: ["backgrid"]
        },

        "bootstrap": {
            deps: ["jquery"]
        },
        "bootstrap-dialog": {
            deps: ["jquery", "lodash", "backbone", "bootstrap"]
        },
        "bootstrap-tabdrop": {
            deps: ["jquery", "bootstrap"]
        },

        "clockPicker": {
            deps: ["jquery"],
            exports: "clockPicker"
        },
        "doTimeout": {
            deps: ["jquery"],
            exports: "doTimeout"
        },
        "form2js": {
            exports: "form2js"
        },
        "i18next": {
            deps: ["jquery", "handlebars"],
            exports: "i18n"
        },
        "js2form": {
            exports: "js2form"
        },
        "jsonEditor": {
            exports: "JSONEditor"
        },
        "moment": {
            exports: "moment"
        },
        "qrcode": {
            exports: "qrcode"
        },
        "selectize": {
            /**
             * sifter, microplugin is additional dependencies for fix release build.
             * @see https://github.com/brianreavis/selectize.js/issues/417
             */
            deps: ["jquery", "sifter", "microplugin"]
        },
        "spin": {
            exports: "spin"
        },
        "lodash": {
            exports: "_"
        },
        "xdate": {
            exports: "xdate"
        },
        "sortable": {
            deps: ["jquery"]
        },
        "react-input-autosize": {
            deps: ["reactAutosizeInputDep"]
        },
        "react-select": {
            deps: ["reactSelectDep"]
        }
    }
});

/*
 * TASK 5.3 -- SUPERSEDED BY NOTHING, AND DELIBERATELY STILL HERE.
 *
 * These two synthetic modules exist because the browserify `dist/` bundles that the `paths`
 * entries above point at read four globals SYNCHRONOUSLY when the file is evaluated --
 * window.React x8, window.ReactDOM x1, window.classNames x4, window.AutosizeInput x1, measured
 * and quoted in NOTES-shims.md section 3.2 B. RequireJS makes that work because a shim's `deps`
 * load before the shimmed file's <script> is inserted, which is the only thing sequencing the
 * assignments below ahead of the reads. Nothing in the source states that ordering.
 *
 * TASK 5.3 removed the need for all four rather than reproducing them in ESM: react-select's own
 * package `main` is plain CommonJS that requires react, react-dom, react-input-autosize and
 * classnames by name, so under Vite the ordering is an ordinary import edge and there is no
 * global to set. Same package, same 1.0.0-rc.2 -- the version design.md's Non-Goals pin is
 * untouched, and no library was substituted.
 *
 * So there is no ESM successor to point at and nothing here to rewrite. These two `define()`s
 * are NOT deleted because the tree is still AMD and RequireJS still loads `main` today; deleting
 * them now would break the running UI for no gain. TASK 5.4 deletes them with the require.config
 * call above, and needs to add nothing in their place.
 */
define("reactAutosizeInputDep", ["react"], (React) => {
    window.React = React;
    return {};
});

define("reactSelectDep", ["react-dom", "react-input-autosize", "classnames"], (ReactDOM, autoSize, classNames) => {
    window.ReactDOM = ReactDOM;
    window.classNames = classNames;
    window.AutosizeInput = autoSize;
    return {};
});

require([
    "org/forgerock/commons/ui/common/util/Constants",
    "org/forgerock/commons/ui/common/main/EventManager",

    // other modules that are necessary to include to startup the app
    "jquery",
    "lodash",
    "backbone",
    "handlebars",
    "i18next",
    "spin",
    "org/forgerock/commons/ui/common/main",
    "org/forgerock/openam/ui/main",
    "config/main",
    "store/index"
], (Constants, EventManager) => {
    EventManager.sendEvent(Constants.EVENT_DEPENDENCIES_LOADED);
});
