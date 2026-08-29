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


/*
 * An aggregator: it had no factory and exported nothing, so every dependency was already loaded
 * purely for its side effects. Side-effect imports preserve that exactly, in the original order.
 * The define carried the named id "org/forgerock/openam/ui/user/dashboard/main", which is this
 * file's own path, so dropping the name changes nothing.
 *
 * The ids are RELATIVE and stay relative. resolve.alias never sees a relative specifier, but none
 * of them needs one: each resolves against this file's own directory to a file that exists, because
 * the source layout already mirrors the module-id layout here. Checked with a Rollup
 * `this.resolve(id, importer)` probe against the real vite.config.js, not assumed.
 */
import "./services/DeviceManagementService";
import "./services/MyApplicationsService";
import "./services/OAuthTokensService";
import "./services/TrustedDevicesService";
import "./views/DashboardView";
/*
 * "./views/DeviceManagementView" stood here and is deliberately dropped. Its target was deleted in
 * 19778b1940 "AME-10804 Add Device Push panel to User Dashboard", which added
 * AuthenticationDevicesView.jsm -- whose exported class is still literally named
 * DeviceManagementView -- and never updated this list. Inside an AMD define([...]) a dangling id is
 * only a string literal, so it has resolved to nothing since that commit; under ESM it is a hard
 * build error. Dropping it preserves current behaviour exactly. It is NOT repointed at
 * AuthenticationDevicesView: that would restore a panel that has not loaded since 19778b1940, which
 * would be a behaviour change rather than a conversion.
 */
import "./views/MyApplicationsView";
import "./views/OAuthTokensView";
import "./views/TrustedDevicesView";
