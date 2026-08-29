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
 * Portions copyright 2014-2016 ForgeRock AS.
 * Portions copyright 2026 3A Systems, LLC.
 */

import $ from "jquery";
import "org/forgerock/commons/ui/common/main/Configuration";
import { getConfiguration as getServerConfiguration } from
    "org/forgerock/openam/ui/common/services/ServerService";
import isRealmChanged from "org/forgerock/openam/ui/common/util/isRealmChanged";
import { get as getSessionToken } from "org/forgerock/openam/ui/user/login/tokens/SessionToken";
import { updateSessionInfo } from "org/forgerock/openam/ui/user/services/SessionService";
import UserProfileView from "UserProfileView";

const obj = {};
const setRequireMapConfig = function (serverInfo) {
    if (serverInfo.kbaEnabled === "true") {
        /*
         * DELIBERATELY NOT A STATIC IMPORT. Design decision D1 keeps this a RUNTIME module-registry
         * lookup: the tab is loaded only when the server reports KBA is enabled, so hoisting it to
         * a static `import` would change it from conditional to unconditional. Task 6.1 owns
         * replacing this `require([...])` with the `import.meta.glob` registry; until then it stays
         * verbatim. Do not convert it in an AMD->ESM batch.
         */
        if (typeof require === "function") {
            require(["org/forgerock/commons/ui/user/profile/UserProfileKBATab"], (tab) => {
                UserProfileView.registerTab(tab);
            });
        } else {
            /*
             * REVIEW FIX. index.html no longer loads RequireJS, so this call is a ReferenceError on
             * the console page -- it threw during startup configuration whenever the server reported
             * kbaEnabled. `env: { amd: true }` means no-undef never flagged it. The guard turns a
             * startup exception into a named message until 6.1 lands the registry.
             */
            console.error("KBA tab not loaded: needs the 6.1 import.meta.glob module registry (D1).");
        }
    }
    return serverInfo;
};

/**
 * Makes a HTTP request to the server to get its configuration
 * @param {Function} successCallback Success callback function
 * @param {Function} errorCallback   Error callback function
 */
obj.getConfiguration = function (successCallback, errorCallback) {
    getServerConfiguration({ suppressEvents: true }).then((response) => {
        setRequireMapConfig(response);
        successCallback(response);
    }, errorCallback);
};

/**
 * Checks if realm has changed. Redirects to switch realm page if so.
 * @returns {Promise} promise empty promise
 */
obj.checkForDifferences = function () {
    const sessionToken = getSessionToken();

    if (sessionToken) {
        return updateSessionInfo(sessionToken).then(() => {
            if (isRealmChanged()) {
                location.href = "#confirmLogin/";
            }
        }, () => {
            // No (valid) session - e.g. anonymous user, or an HttpOnly session cookie that
            // cannot be read and turned out not to reference a live session. Continue without
            // a realm change check rather than stalling page rendering.
            return $.Deferred().resolve();
        });
    } else {
        return $.Deferred().resolve();
    }
};

export default obj;
