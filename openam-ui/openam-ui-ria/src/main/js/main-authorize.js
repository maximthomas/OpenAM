/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2014-2016 ForgeRock AS. All rights reserved.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * Portions Copyrighted 2019-2026 3A Systems LLC.
 */

/*
 * TASK 5.4 (batch B12) -- THE OAUTH2 CONSENT / ERROR ENTRY POINT, NOW AN ES MODULE.
 *
 * This file never contained a define(); it was a `require.config` call plus a top-level runtime
 * `require([...])`. The config block is deleted -- all six ids it bound are `resolve.alias`
 * entries in vite.config.js since TASK 5.2, and the `map` entries for `ThemeManager` and `Router`
 * are aliases too, which is why both are still imported by their short id below rather than by
 * path. The dependency list became static imports.
 *
 * HOW THIS FILE IS LOADED (option c1). Four .ftl pages in the openam-oauth2 module fetch it with
 * `<script data-main="${baseUrl}/XUI/main-authorize" ...>`, and RequireJS injects a CLASSIC script
 * for that, which cannot execute an ES module. D8 and task 10.4 forbid editing those templates, so
 * the build emits an unhashed classic-script STUB at `main-authorize.js` that dynamic-imports the
 * real hashed chunk; see the xui-requirejs-entry-stubs plugin in vite.config.js. Nothing in this
 * file has to know that.
 *
 * `text!` -> `UIUtils.compileTemplate(url, null)` (D22), and the HAND-ROLLED THEME PREFIXING WENT
 * WITH IT. The four template ids were built at runtime as `text!${themePath}${templatePath}` from
 * `Configuration.globalData.theme.path` -- which is a hand re-implementation of the theme-path
 * prefixing compileTemplate already does internally, and a strictly worse one: it had no 404
 * fallback, so a theme with a `path` that did not carry all four templates 404'd rather than
 * falling back to the default copy. compileTemplate with a null `data` argument resolves with the
 * RAW Handlebars source -- exactly what `text!` produced -- prefixes `theme.path` itself and falls
 * back on a 404 (D3). So the prefixing is not lost, it moved to the one implementation of it.
 */

import $ from "jquery";
import _ from "lodash";
import HandleBars from "handlebars";
import Configuration from "org/forgerock/commons/ui/common/main/Configuration";
import Constants from "org/forgerock/openam/ui/common/util/Constants";
import UIUtils from "org/forgerock/commons/ui/common/util/UIUtils";
import Promise from "org/forgerock/openam/ui/common/util/Promise";
import i18nManager from "org/forgerock/commons/ui/common/main/i18nManager";
import ThemeManager from "ThemeManager";
import Router from "Router";
import { configure as configureLoader } from "org/forgerock/commons/ui/common/util/esm/LoaderRuntime";
import warnRetiredConfig from "./warnRetiredConfig.js";

// Helpers for the code that hasn't been properly migrated to require these as explicit dependencies:
window.$ = $;
window._ = _;

var formTemplate,
    baseTemplate,
    footerTemplate,
    loginHeaderTemplate,
    templatePaths = [
        "templates/user/AuthorizeTemplate.html",
        "templates/common/LoginBaseTemplate.html",
        "templates/common/FooterTemplate.html",
        "templates/common/LoginHeaderTemplate.html"
    ],
    data = window.pageData || {},
    KEY_CODE_ENTER = 13,
    KEY_CODE_SPACE = 32,
    dataReady = $.Deferred();

/* global __TARGET_VERSION__ */
/*
 * REVIEW FIX (D22 follow-up). compileTemplate fetches through LoaderRuntime.toUrl, whose baseUrl
 * defaults to "" -- i.e. document-relative. These pages are served from /oauth2/..., NOT from
 * /XUI/, so every template and locale fetch resolved against the wrong root and 404'd (the
 * theme-path attempt AND its fallback), leaving a blank page with nothing logged. Under `text!`
 * RequireJS resolved these against the baseUrl it inferred from `data-main`; that inference is
 * gone, so the baseUrl has to be injected. `pageData.baseUrl` is already "<serverBase>/XUI"
 * (see the six .ftl templates); toUrl appends the separating slash itself.
 *
 * This is deliberately NOT deferred to 6.1 with the rest of LoaderRuntime: `resolveModule` is
 * 6.1's, but `baseUrl`/`urlArgs` are what this batch broke, so this batch restores them.
 *
 * MUST precede i18nManager.init: init() computes `resGetPath` from the runtime at call time.
 */
configureLoader({ baseUrl: data.baseUrl, urlArgs: `v=${__TARGET_VERSION__}` });

/*
 * D6 (task 7.4). Two HEAD requests, deferred to idle, warning if this deployed tree still carries
 * `config/AppConfiguration.js` or `config/ThemeConfiguration.js` -- retired files that an in-place
 * upgrade leaves behind and that nothing reads any more.
 *
 * This page is served from /oauth2/, not /XUI/, so the probe MUST resolve against the baseUrl
 * configured just above: a document-relative url lands on
 * `/oauth2/realms/root/config/AppConfiguration.js` and 404s with the file plainly present, which is
 * design.md D22's regression exactly and fails without a symptom. warnRetiredConfig.js resolves
 * inside its deferred callback, so it reads that baseUrl whenever it runs -- which is what makes
 * this safe rather than the position of this call. That file carries the rest, including why `?v=`
 * is not what defeats the cached 404 and `no-store` is.
 */
warnRetiredConfig();

i18nManager.init({
    paramLang: {
        locale: data.locale || Constants.DEFAULT_LANGUAGE
    },
    defaultLang: Constants.DEFAULT_LANGUAGE,
    nameSpace: "authorize"
});

if (data.oauth2Data) {
    _.each(data.oauth2Data.displayScopes, function (obj) {
        if (_.isEmpty(obj.values)) {
            delete obj.values;
        }
        return obj;
    });

    _.each(data.oauth2Data.displayClaims, function (obj) {
        if (_.isEmpty(obj.values)) {
            delete obj.values;
        }
        return obj;
    });

    if (_.isEmpty(data.oauth2Data.displayScopes) && _.isEmpty(data.oauth2Data.displayClaims)) {
        data.noScopes = true;
    }

    // The CSRF token is a dedicated, random value rendered into pageData by the server (no longer the
    // script-readable SSO cookie value), so the SSO cookie can safely be HttpOnly.
    dataReady.resolve();
} else {
    data.noScopes = true;
    dataReady.resolve();
}

dataReady.then(function () {
    Configuration.globalData = { realm : data.realm };

    Router.currentRoute = {
        navGroup: "user"
    };

    ThemeManager.getTheme().always(function (theme) {
        Promise.all(templatePaths.map((templatePath) => UIUtils.compileTemplate(templatePath, null)))
            .then(([AuthorizeTemplate, LoginBaseTemplate, FooterTemplate, LoginHeaderTemplate]) => {
                data.theme = theme;
                baseTemplate = HandleBars.compile(LoginBaseTemplate);
                formTemplate = HandleBars.compile(AuthorizeTemplate);
                footerTemplate = HandleBars.compile(FooterTemplate);
                loginHeaderTemplate = HandleBars.compile(LoginHeaderTemplate);

                $("#wrapper").html(baseTemplate(data));
                $("#footer").html(footerTemplate(data));
                $("#loginBaseLogo").html(loginHeaderTemplate(data));
                $("#content").html(formTemplate(data)).find(".panel-heading").bind("click keyup", function (e) {
                    // keyup is required so that the collapsed panel can be opened with the keyboard alone,
                    // and without relying on a mouse click event.
                    if (e.type === "keyup" && e.keyCode !== KEY_CODE_ENTER && e.keyCode !== KEY_CODE_SPACE) {
                        return;
                    }
                    $(this).toggleClass("expanded").next(".panel-collapse").slideToggle();
                });
            }, (error) => {
                console.error("main-authorize: templates failed to load", error);
            });
    });
});
