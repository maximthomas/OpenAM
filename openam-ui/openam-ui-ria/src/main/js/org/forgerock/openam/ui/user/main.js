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
 * Portions copyright 2011-2016 ForgeRock AS.
 */


/*
 * An aggregator: it had no factory and exported nothing, so every dependency was already loaded
 * purely for its side effects. Side-effect imports preserve that exactly, in the original order.
 * The define carried the named id "org/forgerock/openam/ui/user/main", which is this file's own
 * path, so dropping the name changes nothing.
 *
 * The ids are RELATIVE and stay relative. resolve.alias never sees a relative specifier, but none
 * of them needs one: each resolves against this file's own directory to a file that exists, because
 * the source layout already mirrors the module-id layout here. Checked with a Rollup
 * `this.resolve(id, importer)` probe against the real vite.config.js, not assumed.
 */

/*
 * "./profile/ChangeSecurityDataDialog" stood here and is deliberately dropped. Its target was
 * deleted in e649bbca1a "CR-8321 - AME-8518 - Align XUI profile page with changes from
 * forgerock-ui-user as part of CUI-91", which never updated this list. Inside an AMD define([...])
 * a dangling id is only a string literal, so it has resolved to nothing since that commit; under
 * ESM it is a hard build error. Dropping it preserves current behaviour exactly and does not
 * restore the dialog.
 */
import "./services/TokenService";
import "./services/SessionService";
import "./services/AuthNService";
import "./services/KBADelegate";
import "./login/RESTLoginHelper";
import "./login/RESTLoginView";
import "./login/RESTConfirmLoginView";
import "./login/RESTLoginDialog";
import "./login/RESTLogoutView";
