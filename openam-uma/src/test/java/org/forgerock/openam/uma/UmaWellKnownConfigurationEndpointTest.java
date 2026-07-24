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
 * Portions copyright 2026 3A Systems, LLC.
 */

package org.forgerock.openam.uma;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class UmaWellKnownConfigurationEndpointTest {

    private UmaWellKnownConfigurationEndpoint endpoint;

    private UmaProviderSettingsFactory providerSettingsFactory;
    private UmaUrisFactory umaUrisFactory;
    private UmaUris umaUris;
    private UmaProviderSettings providerSettings;
    private Context context;
    private RealmTestHelper realmTestHelper;

    @BeforeMethod
    public void setup() throws Exception {

        umaUrisFactory = mock(UmaUrisFactory.class);
        providerSettingsFactory = mock(UmaProviderSettingsFactory.class);

        endpoint = new UmaWellKnownConfigurationEndpoint(umaUrisFactory, providerSettingsFactory);

        // Initialise the static Realm class so Realm.root() works regardless of test ordering; without
        // this the injected CoreWrapper may be null and Realm.root() throws NPE.
        realmTestHelper = new RealmTestHelper();
        realmTestHelper.setupRealmClass();

        // The realm the endpoint resolves from the context; get(...) is stubbed with matchers so the
        // exact realm instance/path does not matter.
        context = new RealmContext(new AttributesContext(new RootContext()), Realm.root());

        umaUris = mock(UmaUris.class);
        providerSettings = mock(UmaProviderSettings.class);
        given(umaUrisFactory.get(any(Context.class), any(Realm.class))).willReturn(umaUris);
        given(providerSettingsFactory.get(anyString())).willReturn(providerSettings);
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
    }

    private void setupProviderSettings() throws NotFoundException, ServerException {
        given(providerSettings.getVersion()).willReturn("VERSION");
        given(umaUris.getIssuer()).willReturn(URI.create("ISSUER"));
        given(providerSettings.getSupportedPATProfiles()).willReturn(Collections.singleton("PAT_PROFILE"));
        given(providerSettings.getSupportedAATProfiles()).willReturn(Collections.singleton("AAT_PROFILE"));
        given(providerSettings.getSupportedRPTProfiles()).willReturn(Collections.singleton("RPT_PROFILE"));
        given(providerSettings.getSupportedPATGrantTypes()).willReturn(Collections.singleton("PAT_GRANT_TYPE"));
        given(providerSettings.getSupportedAATGrantTypes()).willReturn(Collections.singleton("AAT_GRANT_TYPE"));
        given(umaUris.getTokenEndpoint()).willReturn(URI.create("TOKEN_ENDPOINT"));
        given(umaUris.getAuthorizationEndpoint()).willReturn(URI.create("AUTHORIZATION_ENDPOINT"));
        given(umaUris.getTokenIntrospectionEndpoint()).willReturn(URI.create("TOKEN_INTROSPECTION_ENDPOINT"));
        given(umaUris.getResourceSetRegistrationEndpoint()).willReturn(URI.create("RESOURCE_SET_REGISTRATION_ENDPOINT"));
        given(umaUris.getPermissionRegistrationEndpoint()).willReturn(URI.create("PERMISSION_REGISTRATION_ENDPOINT"));
        given(umaUris.getRPTEndpoint()).willReturn(URI.create("RPT_ENDPOINT"));
    }

    private void setupProviderSettingsWithOptionalConfiguration() throws NotFoundException, ServerException {
        setupProviderSettings();
        given(providerSettings.getSupportedClaimTokenProfiles())
                .willReturn(Collections.singleton("CLAIM_TOKEN_PROFILE"));
        given(providerSettings.getSupportedUmaProfiles()).willReturn(Collections.singleton(URI.create("UMA_PROFILE")));
        given(umaUris.getDynamicClientEndpoint()).willReturn(URI.create("DYNAMIC_CLIENT_ENDPOINT"));
        given(umaUris.getRequestingPartyClaimsEndpoint()).willReturn(URI.create("REQUESTING_PARTY_CLAIMS_ENDPOINT"));
    }

    @Test
    public void shouldGetRequiredUmaConfiguration() throws Exception {

        //Given
        setupProviderSettings();

        //When
        Response response = endpoint.getConfiguration(context);

        //Then
        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).contains(entry("version", "VERSION"), entry("issuer", "ISSUER"),
                entry("pat_profiles_supported", Collections.singletonList("PAT_PROFILE")),
                entry("aat_profiles_supported", Collections.singletonList("AAT_PROFILE")),
                entry("rpt_profiles_supported", Collections.singletonList("RPT_PROFILE")),
                entry("pat_grant_types_supported", Collections.singletonList("PAT_GRANT_TYPE")),
                entry("aat_grant_types_supported", Collections.singletonList("AAT_GRANT_TYPE")),
                entry("token_endpoint", "TOKEN_ENDPOINT"), entry("authorization_endpoint", "AUTHORIZATION_ENDPOINT"),
                entry("introspection_endpoint", "TOKEN_INTROSPECTION_ENDPOINT"),
                entry("resource_set_registration_endpoint", "RESOURCE_SET_REGISTRATION_ENDPOINT"),
                entry("permission_registration_endpoint", "PERMISSION_REGISTRATION_ENDPOINT"),
                entry("rpt_endpoint", "RPT_ENDPOINT"));
    }

    @Test
    public void shouldGetOptionalUmaConfiguration() throws Exception {

        //Given
        setupProviderSettingsWithOptionalConfiguration();

        //When
        Response response = endpoint.getConfiguration(context);

        //Then
        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).contains(entry("version", "VERSION"), entry("issuer", "ISSUER"),
                entry("pat_profiles_supported", Collections.singletonList("PAT_PROFILE")),
                entry("aat_profiles_supported", Collections.singletonList("AAT_PROFILE")),
                entry("rpt_profiles_supported", Collections.singletonList("RPT_PROFILE")),
                entry("pat_grant_types_supported", Collections.singletonList("PAT_GRANT_TYPE")),
                entry("aat_grant_types_supported", Collections.singletonList("AAT_GRANT_TYPE")),
                entry("token_endpoint", "TOKEN_ENDPOINT"), entry("authorization_endpoint", "AUTHORIZATION_ENDPOINT"),
                entry("introspection_endpoint", "TOKEN_INTROSPECTION_ENDPOINT"),
                entry("resource_set_registration_endpoint", "RESOURCE_SET_REGISTRATION_ENDPOINT"),
                entry("permission_registration_endpoint", "PERMISSION_REGISTRATION_ENDPOINT"),
                entry("rpt_endpoint", "RPT_ENDPOINT"),
                entry("claim_token_profiles_supported", Collections.singletonList("CLAIM_TOKEN_PROFILE")),
                entry("uma_profiles_supported", Collections.singletonList("UMA_PROFILE")),
                entry("dynamic_client_endpoint", "DYNAMIC_CLIENT_ENDPOINT"),
                entry("requesting_party_claims_endpoint", "REQUESTING_PARTY_CLAIMS_ENDPOINT"));
    }

    @Test(expectedExceptions = NotFoundException.class)
    public void shouldThrowNotFoundExceptionWhenUmaProviderNotConfigured() throws Exception {

        //Given
        doThrow(NotFoundException.class).when(providerSettingsFactory).get(anyString());

        //When
        endpoint.getConfiguration(context);

        //Then -- the endpoint lets it propagate; the shared @ExceptionHandler maps it only under the framework.
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        // getString() yields the serialized wire JSON (URIs rendered as strings), unlike getJson() which
        // returns the raw map still holding URI objects.
        return new ObjectMapper().readValue(response.getEntity().getString(), Map.class);
    }
}
