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
 */

// D21: AM grafts `context` onto the commons Constants object; this must evaluate first.
import "org/forgerock/openam/ui/common/util/Constants";
import Constants from "org/forgerock/commons/ui/common/util/Constants";
import KBADelegate from "org/forgerock/commons/ui/user/delegates/KBADelegate";
import RealmHelper from "org/forgerock/openam/ui/common/util/RealmHelper";

KBADelegate.serviceUrl = RealmHelper.decorateURIWithSubRealm(`/${Constants.context}/json/__subrealm__/${
        Constants.SELF_SERVICE_CONTEXT
    }`);
KBADelegate.baseEntity = RealmHelper.decorateURIWithSubRealm(`json/__subrealm__/${Constants.SELF_SERVICE_CONTEXT}`);

export default KBADelegate;
