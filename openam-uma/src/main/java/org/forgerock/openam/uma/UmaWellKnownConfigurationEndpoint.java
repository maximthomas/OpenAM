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
 * Portions copyright 2025-2026 3A Systems LLC.
 */

package org.forgerock.openam.uma;

import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.utils.CollectionUtils.asList;
import static org.forgerock.openam.utils.CollectionUtils.newList;

import jakarta.inject.Inject;
import java.net.URI;
import java.util.ArrayList;
import java.util.Set;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.services.context.Context;
import org.openidentityplatform.openam.uma.AbstractUmaHttpEndpoint;

/**
 * .well-known configuration for a UMA Authorization Server instance.
 *
 * @since 13.0.0
 */
public class UmaWellKnownConfigurationEndpoint extends AbstractUmaHttpEndpoint {

    private final UmaUrisFactory urisFactory;
    private final UmaProviderSettingsFactory providerSettingsFactory;

    /**
     * Constructs a new instance of a UmaWellKnownConfigurationEndpoint.
     * @param urisFactory An instance of the UmaUrisFactory.
     * @param providerSettingsFactory An instance of the UmaProviderSettingsFactory.
     */
    @Inject
    public UmaWellKnownConfigurationEndpoint(UmaUrisFactory urisFactory,
            UmaProviderSettingsFactory providerSettingsFactory) {
        this.urisFactory = urisFactory;
        this.providerSettingsFactory = providerSettingsFactory;
    }

    /**
     * Gets the configuration for the configured UMA provider for the realm.
     *
     * @param context The request context; the realm is resolved from its {@link RealmContext}.
     * @return The UMA configuration.
     * @throws NotFoundException If no UMA provider has been configured for the realm.
     * @throws ServerException If there is a problem retrieving the configuration for the store.
     */
    @Get
    public Response getConfiguration(@Contextual Context context) throws NotFoundException, ServerException {

        Realm realm = context.asContext(RealmContext.class).getRealm();
        UmaUris umaUris = urisFactory.get(context, realm);
        UmaProviderSettings providerSettings = providerSettingsFactory.get(realm.asPath());

        JsonValue configuration = json(object(
                field("version", providerSettings.getVersion()),
                field("issuer", umaUris.getIssuer()),
                field("pat_profiles_supported", newList(providerSettings.getSupportedPATProfiles())),
                field("aat_profiles_supported", newList(providerSettings.getSupportedAATProfiles())),
                field("rpt_profiles_supported", newList(providerSettings.getSupportedRPTProfiles())),
                field("pat_grant_types_supported", newList(providerSettings.getSupportedPATGrantTypes())),
                field("aat_grant_types_supported", newList(providerSettings.getSupportedAATGrantTypes())),
                field("token_endpoint", umaUris.getTokenEndpoint()),
                field("authorization_endpoint", umaUris.getAuthorizationEndpoint()),
                field("introspection_endpoint", umaUris.getTokenIntrospectionEndpoint()),
                field("resource_set_registration_endpoint", umaUris.getResourceSetRegistrationEndpoint()),
                field("permission_registration_endpoint", umaUris.getPermissionRegistrationEndpoint()),
                field("rpt_endpoint", umaUris.getRPTEndpoint())));

        Set<String> supportedClaimTokenProfiles = providerSettings.getSupportedClaimTokenProfiles();
        if (supportedClaimTokenProfiles != null && !supportedClaimTokenProfiles.isEmpty()) {
            configuration.add("claim_token_profiles_supported", supportedClaimTokenProfiles);
        }
        Set<URI> supportedUmaProfiles = providerSettings.getSupportedUmaProfiles();
        if (supportedUmaProfiles != null && !supportedUmaProfiles.isEmpty()) {
            configuration.add("uma_profiles_supported", supportedUmaProfiles);
        }
        URI dynamicClientEndpoint = umaUris.getDynamicClientEndpoint();
        if (dynamicClientEndpoint != null) {
            configuration.add("dynamic_client_endpoint", dynamicClientEndpoint);
        }
        URI requestingPartyClaimsEndpoint = umaUris.getRequestingPartyClaimsEndpoint();
        if (requestingPartyClaimsEndpoint != null) {
            configuration.add("requesting_party_claims_endpoint", requestingPartyClaimsEndpoint.toString());
        }

        // setEntity(Map) routes to setJson -> application/json; charset=UTF-8.
        return new Response(Status.OK).setEntity(configuration.asMap());
    }
}
