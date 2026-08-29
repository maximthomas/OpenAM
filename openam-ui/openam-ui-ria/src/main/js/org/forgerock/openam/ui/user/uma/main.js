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


/*
 * An aggregator: it had no factory and exported nothing, so every dependency was already loaded
 * purely for its side effects. Side-effect imports preserve that exactly, in the original order.
 *
 * The 19 ids are RELATIVE and stay relative. resolve.alias never sees a relative specifier, but
 * none of them needs one: each resolves against this file's own directory to a file that exists,
 * because the source layout already mirrors the module-id layout here. Checked with a Rollup
 * `this.resolve(id, importer)` probe against the real vite.config.js, not assumed.
 */
import "./models/UMAPolicy";
import "./models/UMAPolicyPermission";
import "./models/UMAPolicyPermissionScope";
import "./models/UMAResourceSetWithPolicy";
import "./models/User";

import "./views/request/ListRequest";
import "./views/request/EditRequest";
import "./views/backgrid/cells/PermissionsCell";
import "./views/history/ListHistory";

import "./views/resource/BasePage";
import "./views/resource/LabelTreeNavigationView";
import "./views/resource/MyLabelsPage";
import "./views/resource/MyResourcesPage";
import "./views/resource/ResourcePage";
import "./views/resource/SharedWithMePage";
import "./views/resource/StarredPage";

import "./views/share/BaseShare";
import "./views/share/CommonShare";
import "./views/share/ShareCounter";
