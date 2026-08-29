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
 * Copyright 2015-2016 ForgeRock AS.
 */

/**
 * @module org/forgerock/openam/ui/user/dashboard/services/DeviceManagementService
 */

// D21: AM grafts `context` onto the commons Constants object; this must evaluate first.
import "org/forgerock/openam/ui/common/util/Constants";
import "jquery";
import AbstractDelegate from "org/forgerock/commons/ui/common/main/AbstractDelegate";
import Configuration from "org/forgerock/commons/ui/common/main/Configuration";
import Constants from "org/forgerock/commons/ui/common/util/Constants";
import fetchUrl from "org/forgerock/openam/ui/common/services/fetchUrl";

const obj = new AbstractDelegate(`${Constants.host}/${Constants.context}/json`);

/**
 * Delete oath device by uuid
 * @param {String} uuid The unique device id
 * @returns {Promise} promise that will contain the response
 */
obj.remove = function (uuid) {
    return obj.serviceCall({
        url: fetchUrl(`/users/${
            encodeURIComponent(Configuration.loggedUser.get("username"))}/devices/2fa/oath/${uuid}`),
        headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
        suppressEvents: true,
        method: "DELETE"
    });
};

/**
 * Set status of the oath skip flag for devices
 * @param {Boolean} skip The flag value
 * @returns {Promise} promise that will contain the response
 */
obj.setDevicesOathSkippable = function (skip) {
    const skipOption = { value: skip };
    return obj.serviceCall({
        url: fetchUrl(`/users/${
            encodeURIComponent(Configuration.loggedUser.get("username"))}/devices/2fa/oath?_action=skip`),
        headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
        data: JSON.stringify(skipOption),
        suppressEvents: true,
        method: "POST"
    });
};

/**
 * Check status of the oath skip flag for devices
 * @returns {Promise} promise that will contain the response
 */
obj.checkDevicesOathSkippable = function () {
    return obj.serviceCall({
        url: fetchUrl(`/users/${
            encodeURIComponent(Configuration.loggedUser.get("username"))}/devices/2fa/oath?_action=check`),
        headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
        suppressEvents: true,
        method: "POST"
    }).then(function (statusData) {
        return statusData.result;
    });
};

/**
 * Get array of oath devices
 * @returns {Promise} promise that will contain the response
 */
obj.getAll = function () {
    return obj.serviceCall({
        url: fetchUrl(`/users/${
            encodeURIComponent(Configuration.loggedUser.get("username"))}/devices/2fa/oath?_queryFilter=true`),
        headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
        suppressEvents: true
    }).then((value) => value.result);
};

export default obj;

/*
 * TASK 5.7. `dashboard/views/AuthenticationDevicesView.jsm:20-23` does
 * `import { remove as removeOAth, getAll as getAllOAth }` from this module, matching the shape of
 * its sibling PushDeviceService.jsm, which exports both as real named functions. This module
 * attaches them to a single default instead, so that import resolved to nothing.
 *
 * NOT converted wholesale to PushDeviceService's named-only shape, because
 * `dashboard/views/DevicesSettingsDialog.js:22` imports this module's DEFAULT and calls
 * `setDevicesOathSkippable` on it. Both consumers are correct; the module has to satisfy both.
 *
 * Detaching the two methods is safe: neither uses `this` -- both close over `obj` directly.
 */
export const remove = obj.remove;
export const getAll = obj.getAll;
