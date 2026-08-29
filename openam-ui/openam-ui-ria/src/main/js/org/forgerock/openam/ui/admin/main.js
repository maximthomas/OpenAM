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

/*
 * An aggregator: it had no factory and exported nothing, so every dependency was already loaded
 * purely for its side effects. Side-effect imports preserve that exactly, in the original order and
 * with the original blank-line grouping. The define carried no named id.
 *
 * The ids are RELATIVE (bar the one absolute org/... id, which is left as it was) and stay
 * relative. resolve.alias never sees a relative specifier, but none of them needs one: each
 * resolves against this file's own directory to a file that exists, because the source layout
 * already mirrors the module-id layout here. Checked with a Rollup `this.resolve(id, importer)`
 * probe against the real vite.config.js, not assumed.
 *
 * Nine ids in the original array were DANGLING -- their targets were deleted upstream and never
 * removed from this list. Inside an AMD define([...]) a dep is only a string literal, so each has
 * resolved to nothing since the commit that deleted it; under ESM each is a hard build error. All
 * nine are dropped, which preserves current behaviour exactly. None is repointed at a
 * similarly-named successor: that would restore a view that has not loaded for years, which would
 * be a behaviour change rather than a conversion. Each drop is recorded at its original site below.
 */
import "./services/SMSServiceUtils";
import "./services/realm/AuthenticationService";
import "./services/realm/DashboardService";
import "./services/global/SitesService";
import "./services/global/ServersService";
import "./services/global/AuthenticationService";
import "./services/global/RealmsService";
import "./services/global/ServicesService";
import "./services/global/ScriptsService";

import "./models/Form";
import "./models/FormCollection";

import "./utils/AdministeredRealmsHelper";
import "./utils/FormHelper";
import "./utils/JSONEditorTheme";
import "./utils/RedirectToLegacyConsole";

/*
 * Dropped here: "./views/realms/agents/AgentsView", deleted in 4d29788e93 "OPENAM-6308 Remove
 * redirect views and use events instead to redirect to JATO".
 *
 * Dropped here: "./views/realms/authentication/chains/CriteriaView", deleted in f7786f88fa
 * "AME-8615 / CR-8399 - Aligned authentication chain view to new designs".
 */
import "./views/realms/authentication/chains/AddChainView";
import "./views/realms/authentication/chains/EditChainView";
import "./views/realms/authentication/chains/EditLinkView";
import "./views/realms/authentication/chains/LinkView";
/*
 * Dropped here: "./views/realms/authentication/chains/LinkInfoView", deleted in f7786f88fa
 * "AME-8615 / CR-8399 - Aligned authentication chain view to new designs".
 */
import "./views/realms/authentication/chains/PostProcessView";
import "./views/realms/authentication/ChainsView";
import "./views/realms/authentication/ModulesView";
import "./views/realms/authentication/modules/EditModuleView";
import "./views/realms/authentication/modules/AddModuleView";
import "./views/realms/authentication/SettingsView";
import "./views/realms/dashboard/DashboardView";
import "./views/realms/dashboard/DashboardTasksView";
/*
 * Dropped here: "./views/realms/dataStores/DataStoresView", deleted in 4d29788e93 "OPENAM-6308
 * Remove redirect views and use events instead to redirect to JATO".
 */
import "./views/realms/authorization/common/AbstractListView";
import "./views/realms/authorization/policies/EditPolicyView";
import "./views/realms/authorization/policySets/PolicySetsView";
import "./views/realms/authorization/policySets/EditPolicySetView";
import "./views/realms/authorization/resourceTypes/ResourceTypesView";
import "./views/realms/authorization/resourceTypes/EditResourceTypeView";
/*
 * Dropped here: "./views/realms/privileges/PrivilegesView", deleted in 4d29788e93 "OPENAM-6308
 * Remove redirect views and use events instead to redirect to JATO".
 */
import "./views/realms/scripts/EditScriptView";
import "./views/realms/scripts/ScriptsView";
/*
 * Dropped here: "./views/realms/sts/STSView" and "./views/realms/subjects/SubjectsView", both
 * deleted in 4d29788e93 "OPENAM-6308 Remove redirect views and use events instead to redirect to
 * JATO".
 */
import "./views/realms/EditRealmView";
import "./views/realms/ListRealmsView";
import "./views/realms/RealmTreeNavigationView";

/*
 * Dropped here: "./views/configuration/server/EditServerDefaultsView", deleted in d1d5e461e9
 * "AME-10024 Add tree navigation for server defaults".
 */
import "./views/configuration/authentication/ListAuthenticationView";
import "./views/configuration/global/ListGlobalServicesView";

import "./views/common/ToggleCardListView";
import "org/forgerock/openam/ui/admin/views/common/Backlink";

/*
 * Dropped here: "./views/deployment/servers/EditServerView", deleted in 74da40d904 "AME-10025
 * updated existing server defaults view so it can be used by any server". A file of that NAME now
 * exists at views/common/server/EditServerView.js, and this id is deliberately NOT repointed at it:
 * that view has not loaded from here since 74da40d904, so repointing would be a behaviour change.
 */
import "./views/deployment/servers/NewServerView";
