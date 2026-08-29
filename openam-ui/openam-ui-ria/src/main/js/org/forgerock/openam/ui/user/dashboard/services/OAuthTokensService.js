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


// D21: AM grafts `context` onto the commons Constants object; this must evaluate first.
import "org/forgerock/openam/ui/common/util/Constants";
import AbstractDelegate from "org/forgerock/commons/ui/common/main/AbstractDelegate";
import Configuration from "org/forgerock/commons/ui/common/main/Configuration";
import Constants from "org/forgerock/commons/ui/common/util/Constants";
import fetchUrl from "org/forgerock/openam/ui/common/services/fetchUrl";

var obj = new AbstractDelegate(`${Constants.host}/${Constants.context}/json`);

obj.getApplications = function () {
    return obj.serviceCall({
        url: fetchUrl(`/users/${
            encodeURIComponent(Configuration.loggedUser.get("username"))}/oauth2/applications?_queryFilter=true`),
        headers: { "Cache-Control": "no-cache", "Accept-API-Version": "protocol=1.0,resource=1.0" }
    });
};

obj.revokeApplication = function (id) {
    return obj.serviceCall({
        url: fetchUrl(
            `/users/${encodeURIComponent(Configuration.loggedUser.get("username"))}/oauth2/applications/${id}`),
        type: "DELETE",
        headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" }
    });
};

export default obj;
