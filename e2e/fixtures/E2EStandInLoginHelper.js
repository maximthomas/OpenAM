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
 * Copyright 2026 3A Systems, LLC.
 */

/**
 * A stand-in login helper, standing for whatever an operator would supply.
 *
 * xui-operator-module.spec.mjs copies this file into the deployed `/XUI` and points
 * `AppConfiguration`'s `loginHelperClass` at it. It is a fixture, not product code, and nothing in
 * the shipped tree references it.
 *
 * It is a file rather than a string literal in the spec because phase 2 has to point the same module
 * at a Vite-built XUI (task 6.6), and a file can be redeployed into a different tree without
 * touching the test that asserts on it.
 *
 * The design goal is the *cheapest honest* stand-in: it delegates every member of the contract to
 * the shipped RESTLoginHelper and only records that it was called, so it proves the app used it
 * without changing a single thing about how login behaves. A stand-in that altered the outcome would
 * be stronger proof of use and a much worse test — a bug in the fixture would be indistinguishable
 * from a bug in the product, and it is the one variant that can lock an operator out of the console.
 *
 * Three things here are load-bearing; see NOTES-operator-module.md for the measurements.
 *
 *   - **AMD, not ESM.** The deployed tree is unbundled and loaded by RequireJS 2.3.7. An `export`
 *     would be a syntax error and the module would never register. Under D1 the fallback is a native
 *     dynamic import instead, so an operator's module changes format even if the capability survives
 *     — which is part of what task 6.6 has to answer.
 *   - **`login` must declare exactly three formal parameters.** SessionManager calls
 *     `_.curry(helper.login)(params)`, and lodash takes the arity from `fn.length`. Written with rest
 *     args, `length` is 0, `_.curry` invokes immediately with only `params`, the callbacks are never
 *     passed — and login hangs with no error anywhere. The same applies to the other two.
 *   - **Delegate through `RESTLoginHelper`, not `this`.** The real `login` does `var self = this; …
 *     self.setSuccessURL(...)`, and SessionManager binds the helper it loaded as `this`. Calling the
 *     real object keeps `this` pointing at the real helper, so its internals resolve even though the
 *     stand-in never declares them.
 */
define([
    "org/forgerock/openam/ui/user/login/RESTLoginHelper"
], function (RESTLoginHelper) {
    /**
     * The observable. Written by this module and by nothing else, so the spec's assertion cannot be
     * satisfied by an app that resolved the module and then ignored it — which is why the test
     * asserts on `calls` rather than on `loaded`.
     */
    var marker = window.__e2eLoginHelper = {
        loaded: true,
        moduleId: "config/E2EStandInLoginHelper",
        delegatesTo: "org/forgerock/openam/ui/user/login/RESTLoginHelper",
        calls: []
    };

    // Inherit every member this file does not name — setSuccessURL, filterUrlParams,
    // getSuccessfulLoginUrlParams and the AbstractConfigurationAware bits — rather than losing them.
    // SessionManager only ever calls the three below, but the module it loads should still be a
    // usable login helper for anything that reaches it another way.
    var standIn = Object.create(RESTLoginHelper);

    standIn.login = function (params, successCallback, errorCallback) {
        marker.calls.push("login");
        return RESTLoginHelper.login(params, successCallback, errorCallback);
    };

    standIn.logout = function (successCallback, errorCallback) {
        marker.calls.push("logout");
        return RESTLoginHelper.logout(successCallback, errorCallback);
    };

    standIn.getLoggedUser = function (successCallback, errorCallback) {
        marker.calls.push("getLoggedUser");
        return RESTLoginHelper.getLoggedUser(successCallback, errorCallback);
    };

    return standIn;
});
