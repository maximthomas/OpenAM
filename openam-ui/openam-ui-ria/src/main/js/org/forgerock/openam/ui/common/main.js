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
 * Copyright 2014-2016 ForgeRock AS.
 */

/*
 * An aggregator: it had no factory and exported nothing, so every dependency was already loaded
 * purely for its side effects. Side-effect imports preserve that exactly.
 *
 * The four ids are RELATIVE and stay relative. They cannot be aliased -- resolve.alias never sees a
 * relative specifier -- but they need no alias: each one resolves against this file's own directory
 * to a file that exists (common/util/Constants.js, common/util/RealmHelper.js,
 * common/services/SiteConfigurationService.js, common/components/TemplateBasedView.js), because the
 * source layout already mirrors the module-id layout here.
 */
import "./util/Constants";
import "./util/RealmHelper";
import "./services/SiteConfigurationService";
import "./components/TemplateBasedView";
