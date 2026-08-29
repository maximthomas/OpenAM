/**
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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2025 3A Systems LLC.
 */

require.config({
    map: {
        "*" : {
            "ThemeManager" : "org/forgerock/openam/ui/common/util/ThemeManager",
            "Router": "org/forgerock/openam/ui/common/SingleRouteRouter",
            // TODO: Remove this when there are no longer any references to the "underscore" dependency
            "underscore"   : "lodash"
        }
    },
    /*
     * TASK 5.2. Superseded by vite.config.js's resolve.alias, and deliberately still here -- see
     * the longer note in main.js. This block binds six ids; all six have alias entries.
     *
     * Two things measured here that main.js's block does not show. `redux` is inert in this
     * entry: nothing it loads imports redux (only store/index.jsm and store/reducers/index.jsm
     * do, and they are reached from main.js alone). And `text` has no successor at all --
     * requirejs-text is an AMD loader plugin that cannot be imported under ESM; TASK 5.5 owns
     * the `text!` call sites, including the runtime-built one in this file.
     */
    paths: {
        "handlebars": "libs/handlebars-4.7.7",
        "i18next": "libs/i18next-1.7.3-min",
        "jquery": "libs/jquery-3.7.1-min",
        "lodash": "libs/lodash-3.10.1-min",
        "redux": "libs/redux-3.5.2-min",
        "text": "libs/text-2.0.15"
    },
    /*
     * TASK 5.2. All three entries here are superseded, and two of the three were already dead.
     *
     * `handlebars` has a shim in THIS file and in main-authorize.js but NOT in main.js -- a
     * divergence between the three entry points, and a harmless one: handlebars/dist/handlebars.js
     * calls define(), so RequireJS ignores the exports field anyway, and the global it sets is
     * `Handlebars`, not `handlebars`, so if it ever became live it would resolve to undefined.
     * `lodash` is dead for the same reason. Only i18next -> i18n was load-bearing, and its
     * "handlebars" dep is fiction: i18next.min.js contains zero occurrences of Handlebars.
     *
     * i18next is now vite.config.js's alias to src/main/js/shims/i18next.js, which fixes both the
     * specifier (the bare name resolves to a Node build that requires fs) and the ordering (it
     * reads jQuery from a global at evaluation and falls back SILENTLY if it is missing).
     */
    shim: {
        "handlebars": {
            exports: "handlebars"
        },
        "i18next": {
            deps: ["jquery", "handlebars"],
            exports: "i18n"
        },
        "lodash": {
            exports: "_"
        }
    }
});

require([
    "jquery",
    "handlebars",
    "org/forgerock/commons/ui/common/main/Configuration",
    "org/forgerock/openam/ui/common/util/Constants",
    "text!templates/user/DeviceTemplate.html",
    "text!templates/user/DeviceDoneTemplate.html",
    "text!templates/common/LoginBaseTemplate.html",
    "text!templates/common/FooterTemplate.html",
    "text!templates/common/LoginHeaderTemplate.html",
    "org/forgerock/commons/ui/common/main/i18nManager",
    "ThemeManager",
    "Router"
], function ($, HandleBars, Configuration, Constants, DeviceTemplate, DeviceDoneTemplate,
            LoginBaseTemplate, FooterTemplate, LoginHeaderTemplate, i18nManager, ThemeManager, Router) {
    var data = window.pageData,
        template = data.done ? DeviceDoneTemplate : DeviceTemplate;

    i18nManager.init({
        paramLang: {
            locale: data.locale
        },
        defaultLang: Constants.DEFAULT_LANGUAGE,
        nameSpace: "device"
    });

    Configuration.globalData = { realm : data.realm };
    Router.currentRoute = {
        navGroup: "user"
    };

    ThemeManager.getTheme().always(function (theme) {
        data.theme = theme;

        $("#wrapper").html(HandleBars.compile(LoginBaseTemplate)(data));
        $("#footer").html(HandleBars.compile(FooterTemplate)(data));
        $("#loginBaseLogo").html(HandleBars.compile(LoginHeaderTemplate)(data));
        $("#content").html(HandleBars.compile(template)(data));
    });
});
