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
 * Portions copyright 2025-2026 3A Systems LLC.
 */

/*
 * TASK 5.4 (batch B12) -- THE DEVICE-FLOW ENTRY POINT, NOW AN ES MODULE.
 *
 * This file never contained a define(); it was a `require.config` call plus a top-level runtime
 * `require([...])`. The config block is deleted -- all six ids it bound are `resolve.alias`
 * entries in vite.config.js since TASK 5.2, and the `map` entries for `ThemeManager` and `Router`
 * are aliases too, which is why both are still imported by their short id below rather than by
 * path. The dependency list became static imports.
 *
 * HOW THIS FILE IS LOADED (option c1). CodeVerificationForm.ftl:37 and CodeThanks.ftl:37 in the
 * openam-oauth2 module fetch it with `<script data-main="${baseUrl}/XUI/main-device" ...>`, and
 * RequireJS injects a CLASSIC script for that, which cannot execute an ES module. D8 and task 10.4
 * forbid editing those templates, so the build emits an unhashed classic-script STUB at
 * `main-device.js` that dynamic-imports the real hashed chunk; see the
 * xui-requirejs-entry-stubs plugin in vite.config.js. Nothing in this file has to know that.
 *
 * `text!` -> `UIUtils.compileTemplate(url, null)` (D22). The five templates were static `text!`
 * dependencies resolved by requirejs-text, which has no ES module form. compileTemplate with a
 * null `data` argument resolves with the RAW Handlebars source -- exactly what `text!` produced --
 * and routes the fetch through ThemeManager's theme-path-first + 404-fallback lookup.
 *
 * THAT IS A WIDENING, NOT A PORT, AND IT IS DELIBERATE (review finding, accepted by the owner).
 * These five were STATIC `text!` ids at the base SHA -- resolved against the RequireJS baseUrl
 * with no theme prefixing at all -- so unlike main-authorize's hand-rolled prefixing they were
 * never theme-overridable. compileTemplate prefixes theme.path for all of them, so they become
 * overridable here for the first time. The shipped default theme has `path: ""`, so nothing
 * changes out of the box; an operator whose theme directory already contains one of these paths
 * (LoginBaseTemplate.html is themed on the login page today) will see this page pick it up. That
 * is D3 surface, recorded in D22 as an accepted behaviour change. A Vite `?raw` import would
 * instead bundle them and foreclose the override entirely.
 */

import $ from "jquery";
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

var data = window.pageData;

/* global __TARGET_VERSION__ */
/*
 * REVIEW FIX (D22 follow-up) -- see main-authorize.js for the full reasoning. These pages are
 * served from /oauth2/..., so the default document-relative baseUrl made every template and
 * locale fetch 404. MUST precede i18nManager.init, which computes `resGetPath` at call time.
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
        locale: data.locale
    },
    defaultLang: Constants.DEFAULT_LANGUAGE,
    nameSpace: "device"
});

Configuration.globalData = { realm : data.realm };
Router.currentRoute = {
    navGroup: "user"
};

/*
 * The templates are fetched INSIDE this callback and not before it, because compileTemplate calls
 * ThemeManager.getTheme() itself and getTheme() reads Configuration.globalData.realm and
 * Router.currentRoute, both assigned just above. The second call is not a second round trip: with
 * neither the theme name nor the admin flag changed, getTheme resolves synchronously with the
 * cached Configuration.globalData.theme.
 */
ThemeManager.getTheme().always(function (theme) {
    data.theme = theme;

    Promise.all([
        UIUtils.compileTemplate("templates/user/DeviceTemplate.html", null),
        UIUtils.compileTemplate("templates/user/DeviceDoneTemplate.html", null),
        UIUtils.compileTemplate("templates/common/LoginBaseTemplate.html", null),
        UIUtils.compileTemplate("templates/common/FooterTemplate.html", null),
        UIUtils.compileTemplate("templates/common/LoginHeaderTemplate.html", null)
    ]).then(([DeviceTemplate, DeviceDoneTemplate, LoginBaseTemplate, FooterTemplate, LoginHeaderTemplate]) => {
        const template = data.done ? DeviceDoneTemplate : DeviceTemplate;

        $("#wrapper").html(HandleBars.compile(LoginBaseTemplate)(data));
        $("#footer").html(HandleBars.compile(FooterTemplate)(data));
        $("#loginBaseLogo").html(HandleBars.compile(LoginHeaderTemplate)(data));
        $("#content").html(HandleBars.compile(template)(data));
    }, (error) => {
        console.error("main-device: templates failed to load", error);
    });
});
