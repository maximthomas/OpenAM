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

package org.forgerock.openam.uma;

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
import org.forgerock.oauth2.core.OAuth2Uris;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.oauth2.OAuth2UrisFactory;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Covers the base-URL resolution in {@link UmaUrisFactory#get(Context, Realm)}.
 *
 * <p>This is the gap that let {@code /uma/.well-known/uma-configuration} ship broken in phase 4: the method
 * asked for a CREST {@link HttpContext} unconditionally, and a plain CHF chain
 * ({@code HttpFrameworkServlet -> Endpoints.from}) has none, so every live request became a 500. Neither
 * {@code UmaWellKnownConfigurationEndpointTest} nor {@code UmaRouterIT} caught it because both
 * <strong>mock {@code UmaUrisFactory}</strong> -- so the real resolution never ran under test at all.
 */
public class UmaUrisFactoryTest {

    private static final String BASE_URL = "http://openam.example.org:8080/openam/uma";

    private UmaUrisFactory factory;
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

        OAuth2UrisFactory oAuth2UrisFactory = mock(OAuth2UrisFactory.class);
        given(oAuth2UrisFactory.get(any(Context.class), any(Realm.class))).willReturn(mock(OAuth2Uris.class));

        UmaProviderSettingsFactory settingsFactory = mock(UmaProviderSettingsFactory.class);
        given(settingsFactory.get(anyString())).willReturn(mock(UmaProviderSettings.class));

        factory = new UmaUrisFactory(oAuth2UrisFactory, settingsFactory, baseURLProviderFactory,
                mock(JacksonRepresentationFactory.class));
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
    }

    /**
     * The regression: a CHF context carries the servlet request in its {@link AttributesContext} and no
     * {@link HttpContext} at all. Before the fix this threw
     * {@code IllegalArgumentException: No context of type ...HttpContext found}, which the shared
     * {@code @ExceptionHandler} turned into the live 500.
     */
    @Test
    public void resolvesBaseUrlFromTheServletRequestWhenThereIsNoHttpContext() throws Exception {
        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        given(baseUrlProvider.getRealmURL(eq(servletRequest), eq("/uma"), any(Realm.class))).willReturn(BASE_URL);

        AttributesContext attributes = new AttributesContext(new RootContext());
        attributes.getAttributes().put(HttpServletRequest.class.getName(), servletRequest);
        Context context = new RealmContext(attributes, realm);

        UmaUris uris = factory.get(context, realm);

        assertThat(uris).isNotNull();
        verify(baseUrlProvider).getRealmURL(eq(servletRequest), eq("/uma"), any(Realm.class));
        verify(baseUrlProvider, never()).getRealmURL(any(HttpContext.class), anyString(), any(Realm.class));
    }

    /**
     * A chain carrying neither transport must fail by name rather than by accident. Letting
     * {@code asContext(HttpContext.class)} raise {@code IllegalArgumentException} here would reproduce the
     * phase-4 500 exactly -- an unmapped runtime exception with a message about a CREST type -- so this pins
     * the deliberate {@link ServerException} instead, and pins that a null servlet request is never handed to
     * the provider.
     *
     * <p>The {@link HttpContext} branch itself is not exercised: {@code HttpContext} is final with no public
     * test-friendly constructor, and today {@code UmaWellKnownConfigurationEndpoint} is the only caller, over
     * CHF. Note that the branch would not be reached even under {@code /json} — that path runs through the
     * same {@code HttpFrameworkServlet}, so the servlet request is present there too; it exists only for a
     * chain assembled without one.
     */
    @Test
    public void failsWithANamedErrorWhenTheChainCarriesNoTransport() throws Exception {
        // An AttributesContext that exists but holds no servlet request: the lookup must not stop at
        // "AttributesContext present" and must not hand a null request to the provider.
        Context context = new RealmContext(new AttributesContext(new RootContext()), realm);

        assertThatThrownBy(() -> factory.get(context, realm))
                .isInstanceOf(ServerException.class)
                .hasMessageContaining("neither a servlet request nor an HttpContext");

        verify(baseUrlProvider, never()).getRealmURL(any(HttpServletRequest.class), anyString(), any(Realm.class));
    }
}
