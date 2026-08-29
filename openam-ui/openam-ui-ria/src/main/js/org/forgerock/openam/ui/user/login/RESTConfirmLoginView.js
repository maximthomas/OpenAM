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
 * Copyright 2011-2016 ForgeRock AS.
 */

import i18next from "i18next";
import AbstractView from "org/forgerock/commons/ui/common/main/AbstractView";
import EventManager from "org/forgerock/commons/ui/common/main/EventManager";
import "org/forgerock/commons/ui/common/main/Configuration";
import Constants from "org/forgerock/openam/ui/common/util/Constants";
import isRealmChanged from "org/forgerock/openam/ui/common/util/isRealmChanged";
import "org/forgerock/openam/ui/user/login/RESTLoginHelper";
import logout from "org/forgerock/openam/ui/user/login/logout";

const ConfirmLoginView = AbstractView.extend({
    template: "templates/openam/ReturnToLoginTemplate.html",
    baseTemplate: "templates/common/LoginBaseTemplate.html",
    data: {},
    render () {
        if (isRealmChanged()) {
            logout().always(() => {
                this.data.title = i18next.t("common.user.loggedOutOfPreviousSite");
                this.data.linkTitle = i18next.t("common.user.logInToNewSite");
                this.parentRender();
            });
        } else {
            EventManager.sendEvent(Constants.EVENT_HANDLE_DEFAULT_ROUTE);
        }
    }
});

export default new ConfirmLoginView();
