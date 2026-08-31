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
 * A stand-in login helper for a Vite-built XUI, standing for whatever an operator would supply.
 *
 * IT IS A FIXTURE, NOT PRODUCT CODE, AND IT MUST STAY IN `OpenAM/e2e/fixtures/`. Do not move or
 * copy it next to the configuration that names it, however much it looks like it belongs there.
 * `moduleRegistry.js` builds the module table from three `import.meta.glob` calls, each rooted in
 * product source: `/src/main/js/**` and the `esm/**` trees of the `@openidentityplatform/ui-commons`
 * and `@openidentityplatform/ui-user` packages — all three over `.js`, `.jsm` and `.jsx` alike, so
 * renaming the extension is not an escape either. A copy under any of them puts
 * `config/E2EStandInLoginHelper` *in* the table, `resolveModule` answers from the table, and the
 * deployed-instance fallback this file exists to exercise is never reached. The module still runs
 * and every behavioural assertion still passes, so the test goes green while testing the wrong
 * branch. That is the absence guarantee, and the reasoning and the other ways to break it are in
 * the header of `xui/xui-operator-module.spec.mjs`; the spec's HTTP assertion on the module's
 * unhashed URL is the guard that catches it.
 *
 * ESM, not AMD: under D1 the module is reached by a native dynamic import of
 * `<XUI root>/config/E2EStandInLoginHelper.js?v=<version>` (moduleRegistry's
 * `loadFromDeployedInstance`), so `define` is not defined and an AMD body dies at evaluation with a
 * bare `ReferenceError`. The default export is what `LoaderRuntime.unwrapModule` hands to
 * `SessionManager`.
 *
 * SELF-CONTAINED, AND THAT IS NOT A SIMPLIFICATION. The AMD fixture did `Object.create(
 * RESTLoginHelper)` and delegated. That has no channel here: the deployed page has no import map,
 * so a bare specifier such as "org/forgerock/openam/ui/user/login/RESTLoginHelper" throws
 * `TypeError: Failed to resolve module specifier`; the only globals the XUI adds are `$`/`jQuery`;
 * and RESTLoginHelper has no chunk of its own in the emitted tree to reach by relative URL. So this
 * module re-implements the three members of the contract against AM's REST API instead, deriving
 * the AM base from `document.baseURI` exactly as the loader derives the fallback URL.
 *
 * Three things here are load-bearing:
 *
 *   - **`login` declares exactly three formal parameters.** `SessionManager.login` calls
 *     `_.curry(helper.login)(params)` and lodash reads the arity off `fn.length`. Written
 *     `login (...args)`, `length` is 0, `_.curry` invokes immediately with only `params`, the
 *     callbacks are never passed, and the form submit goes nowhere with no error anywhere. The same
 *     applies to `logout` and `getLoggedUser`, which take two. Never use rest args here, and never
 *     let a build step transpile this file into them.
 *   - **The three members return `undefined`, not a promise.** `ModuleLoader.promiseWrapper` does
 *     `$.when(functionToCall(success, error))` and treats any non-undefined return as the outcome;
 *     RESTLoginHelper.login returns undefined for the same reason.
 *   - **The user object must answer `uiroles` and `hasRole`.** `Router.checkRole` reads
 *     `loggedUser.uiroles`, AMConfig's EVENT_HANDLE_DEFAULT_ROUTE reads it again to choose the
 *     landing route, and EVENT_AUTHENTICATED calls `loggedUser.hasRole(...)`. A plain
 *     `{ id, username }` gets as far as leaving `#login` and then throws.
 *
 * ASSUMED, NOT DISCOVERED: that the instance issues a JS-readable session cookie named
 * `iPlanetDirectoryPro`. The product reads that name from `Configuration.globalData.auth.cookieName`
 * (`SessionToken.jsm`) and this file hardcodes it (`SESSION_COOKIE` below), so a renamed cookie, or
 * an HttpOnly one — the case `xui/xui-httponly.spec.mjs` covers — leaves `forgetSessionCookie()`
 * deleting nothing and logout stuck at `#logout/`. Only a root-realm instance with the standard
 * configuration has been exercised.
 */

/** The observable. Written by this module and by nothing else. */
const marker = window.__e2eLoginHelper = {
    loaded: true,
    moduleId: "config/E2EStandInLoginHelper",
    // Null, and nothing reads it. Kept because it is the honest answer to the question the AMD
    // fixture's marker answered with a module ID: an operator's ESM module has no channel to a
    // shipped one, so there is nothing here to delegate to (see the header above, and the D1/D6
    // section of xui/xui-operator-module.spec.mjs). The assertion that used to read it was deleted
    // with the delegation, rather than adapted.
    delegatesTo: null,
    calls: []
};

/**
 * The AM context root, derived from the deployed tree's own location.
 *
 * `document.baseURI` is `<serverBase>/<context>/XUI/#<route>` — the same anchor the loader's
 * fallback URL is derived from — so `..` is the context root whatever the context path is called
 * and whatever route the page is on. `new URL` discards the fragment.
 */
const AM_ROOT = new URL("..", document.baseURI).href;

const CREST_V2 = { "Accept-API-Version": "protocol=1.0,resource=2.0" };
const CREST_V3 = { "Accept-API-Version": "protocol=1.0,resource=3.0" };

function rest (path, options) {
    const opts = options || {};
    return fetch(`${AM_ROOT}json${path}`, {
        credentials: "same-origin",
        method: opts.method || "GET",
        headers: Object.assign({ "Content-Type": "application/json" }, opts.headers || {}),
        body: opts.body
    });
}

/** `?realm=…` when the login form is scoped to a sub-realm, and nothing otherwise. */
function realmQuery (params) {
    const realm = params && (params.realm || params.subRealm);
    return realm && realm !== "/" ? `?realm=${encodeURIComponent(realm)}` : "";
}

/**
 * The two-step `/json/authenticate` exchange, filling the callbacks the login form collected.
 *
 * This is RESTLoginHelper's flow — `getRequirements` then `submitRequirements` — reduced to the
 * single-stage username/password case, and it reads `callback_<n>` out of `params` by the same
 * convention `RESTLoginView` writes them by. AM sets the session cookie itself on the response, so
 * nothing here has to write one.
 */
async function authenticate (params) {
    const query = realmQuery(params);
    const first = await rest(`/authenticate${query}`, { method: "POST", headers: CREST_V2 });
    if (!first.ok) { throw new Error(`authenticate (requirements) answered ${first.status}`); }

    const requirements = await first.json();
    (requirements.callbacks || []).forEach((callback, index) => {
        const supplied = params[`callback_${index}`];
        if (supplied !== undefined && callback.input && callback.input.length) {
            callback.input[0].value = supplied;
        }
    });

    const second = await rest(`/authenticate${query}`, {
        method: "POST",
        headers: CREST_V2,
        body: JSON.stringify(requirements)
    });
    const result = second.ok ? await second.json() : null;
    if (!result || !(result.tokenId || (result.successUrl && !result.authId))) {
        throw new Error(`authentication did not complete (${second.status})`);
    }
    return result;
}

/**
 * A user good enough for everything the console asks of `Configuration.loggedUser`.
 *
 * `uiroles` is derived the way `UserModel.parse` derives it, `ui-user` included, because the router
 * and AMConfig both branch on it.
 */
function toUser (identity, attributes) {
    const raw = attributes.roles;
    const uiroles = Array.isArray(raw) ? raw.slice() : (typeof raw === "string" ? raw.split(",") : []);
    if (uiroles.indexOf("ui-user") === -1) { uiroles.push("ui-user"); }

    const values = Object.assign({}, attributes, {
        id: identity.id,
        realm: identity.realm,
        uid: attributes.uid || [identity.id]
    });

    return {
        id: identity.id,
        uiroles,
        attributes: values,
        get (name) { return values[name]; },
        has (name) { return values[name] !== undefined; },
        toJSON () { return Object.assign({}, values); },
        hasRole (roles) {
            const wanted = Array.isArray(roles) ? roles : [roles];
            return wanted.some((role) => uiroles.indexOf(role) !== -1);
        }
    };
}

/**
 * The session cookie the XUI reads back through `SessionToken.get`.
 *
 * Removing it is part of the contract, not tidying: `SiteConfigurationService.checkForDifferences`
 * — which `EVENT_CHANGE_VIEW` awaits before it will route anywhere — branches on
 * `SessionToken.get()`, and the shipped helper's `logout` reaches
 * `removeSessionToken()` for exactly this reason. AM does not clear the cookie on the logout
 * response, so a stand-in that only ends the session server-side leaves the XUI stuck on
 * `#logout/`.
 */
const SESSION_COOKIE = "iPlanetDirectoryPro";

function forgetSessionCookie () {
    const labels = window.location.hostname.split(".");
    const domains = [""];
    for (let i = 0; i + 1 < labels.length; i++) { domains.push(labels.slice(i).join(".")); }
    domains.forEach((domain) => {
        document.cookie = `${SESSION_COOKIE}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/${
            domain ? `;domain=${domain}` : ""}`;
    });
}

/** The user the session cookie identifies, or null when there is no session. */
async function currentUser () {
    const session = await rest("/users?_action=idFromSession", { method: "POST", headers: CREST_V2 });
    if (!session.ok) { return null; }

    const identity = await session.json();
    const profile = await rest(`/users/${encodeURIComponent(identity.id)}`, { headers: CREST_V3 });
    return toUser(identity, profile.ok ? await profile.json() : {});
}

export default {
    login (params, successCallback, errorCallback) {
        marker.calls.push("login");
        authenticate(params || {})
            .then(currentUser)
            .then((user) => {
                if (!user) { throw new Error("authenticated, but no session could be read back"); }
                successCallback(user);
            })
            .catch((error) => { errorCallback(String(error && error.message ? error.message : error)); });
    },

    logout (successCallback, errorCallback) {
        marker.calls.push("logout");
        rest("/sessions?_action=logout", { method: "POST", headers: CREST_V2 })
            .then((response) => (response.ok ? response.json() : {}), () => ({}))
            .then((response) => {
                forgetSessionCookie();
                successCallback(response);
            }, errorCallback);
    },

    getLoggedUser (successCallback, errorCallback) {
        marker.calls.push("getLoggedUser");
        currentUser()
            .then((user) => { if (user) { successCallback(user); } else { errorCallback(); } })
            .catch(() => { errorCallback(); });
    },

    /*
     * Members of the login-helper shape that nothing reaches through `loginHelperClass`. Every
     * caller of `setSuccessURL`, `filterUrlParams` and `getSuccessfulLoginUrlParams` — RESTLoginView,
     * RESTLogoutView, SessionExpiredView — imports the shipped `RESTLoginHelper` directly and calls
     * it there, measured in NOTES-operator-module.md section 1; `SessionManager` is the only thing
     * that resolves `loginHelperClass`, and it calls only the three above. So these are here for
     * shape, and replacing the login helper does not replace them.
     */
    getSuccessfulLoginUrlParams () { return {}; },
    setSuccessURL (tokenId, successUrl) { return Promise.resolve(successUrl); },
    filterUrlParams () { return ""; }
};
