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
 * Copyright 2026 3A Systems LLC.
 */

package org.forgerock.openam.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.json.resource.http.HttpContext;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Uris;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Covers the base-URL resolution in {@link OAuth2UrisFactory#get(Context, Realm)}.
 *
 * <p>This is the <em>second</em> half of the phase-4 regression that took
 * {@code /uma/.well-known/uma-configuration} down: {@code UmaUrisFactory} delegates here, so fixing only the
 * UMA side still produced a 500. {@code UmaUrisFactoryTest} cannot cover it — that test mocks
 * {@code OAuth2UrisFactory}, which puts a mock exactly where this bug lived, the same blind spot
 * {@code UmaRouterIT} had. Hence a test that drives the real factory.
 */
public class OAuth2UrisFactoryTest {

    private static final String BASE_URL = "http://openam.example.org:8080/openam/oauth2";
    private static final String ROOT_URL = "http://openam.example.org:8080/openam";

    private OAuth2UrisFactory factory;
    private BaseURLProvider baseUrlProvider;
    private RealmTestHelper realmTestHelper;
    private Realm realm;

    @BeforeMethod
    public void setup() throws Exception {
        realmTestHelper = new RealmTestHelper();
        realmTestHelper.setupRealmClass();
        realm = Realm.root();

        baseUrlProvider = mock(BaseURLProvider.class);
        BaseURLProviderFactory baseURLProviderFactory = mock(BaseURLProviderFactory.class);
        given(baseURLProviderFactory.get(anyString())).willReturn(baseUrlProvider);

        OAuth2ProviderSettingsFactory settingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        given(settingsFactory.get(any(Context.class))).willReturn(mock(OAuth2ProviderSettings.class));

        factory = new OAuth2UrisFactory(settingsFactory, baseURLProviderFactory);
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
    }

    /**
     * The regression: a CHF context carries the servlet request in its {@link AttributesContext} and no
     * {@link HttpContext} at all. Before the fix both {@code getRealmURL} and {@code getRootURL} were called
     * with {@code context.asContext(HttpContext.class)}, which threw before either could run.
     */
    @Test
    public void resolvesBaseUrlFromTheServletRequestWhenThereIsNoHttpContext() throws Exception {
        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        given(baseUrlProvider.getRealmURL(eq(servletRequest), eq("/oauth2"), any(Realm.class))).willReturn(BASE_URL);
        given(baseUrlProvider.getRootURL(eq(servletRequest))).willReturn(ROOT_URL);

        AttributesContext attributes = new AttributesContext(new RootContext());
        attributes.getAttributes().put(HttpServletRequest.class.getName(), servletRequest);
        Context context = new RealmContext(attributes, realm);

        OAuth2Uris uris = factory.get(context, realm);

        assertThat(uris).isNotNull();
        assertThat(uris.getAuthorizationEndpoint()).isEqualTo(BASE_URL + "/authorize");
        verify(baseUrlProvider).getRealmURL(eq(servletRequest), eq("/oauth2"), any(Realm.class));
        verify(baseUrlProvider).getRootURL(eq(servletRequest));
        verify(baseUrlProvider, never()).getRealmURL(any(HttpContext.class), anyString(), any(Realm.class));
        verify(baseUrlProvider, never()).getRootURL(any(HttpContext.class));
    }

    /**
     * A chain carrying neither transport must fail by name. Letting {@code asContext(HttpContext.class)} raise
     * {@code IllegalArgumentException} here would reproduce the shipped 500 exactly — an unmapped runtime
     * exception whose message names a CREST type — so the deliberate {@link ServerException} is pinned
     * instead, along with the fact that a null servlet request is never handed to the provider.
     */
    @Test
    public void failsWithANamedErrorWhenTheChainCarriesNoTransport() throws Exception {
        Context context = new RealmContext(new AttributesContext(new RootContext()), realm);

        assertThatThrownBy(() -> factory.get(context, realm))
                .isInstanceOf(ServerException.class)
                .hasMessageContaining("neither a servlet request nor an HttpContext");

        verify(baseUrlProvider, never()).getRealmURL(any(HttpServletRequest.class), anyString(), any(Realm.class));
        verify(baseUrlProvider, never()).getRootURL(any(HttpServletRequest.class));
    }
}
