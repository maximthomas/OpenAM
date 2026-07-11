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
 * Copyright 2016 ForgeRock AS.
 * Portions copyright 2025-2026 3A Systems, LLC.
 */
package org.forgerock.oauth2.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.mockito.ArgumentCaptor;
import org.restlet.engine.adapter.HttpRequest;
import org.forgerock.openam.rest.jakarta.servlet.internal.ServletCall;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

public class OAuth2RequestFactoryTest {

    private static final String CLIENT_ID = "client_id";

    private ClientRegistrationStore clientRegistrationStore;
    private OAuth2RequestFactory factory;
    private HttpServletRequest httpServletRequest;

    @BeforeMethod
    public void setUpTest() {
        clientRegistrationStore = mock(ClientRegistrationStore.class);
        JacksonRepresentationFactory jacksonRepresentationFactory =
                new JacksonRepresentationFactory(new ObjectMapper());
        factory = new OAuth2RequestFactory(jacksonRepresentationFactory, clientRegistrationStore);
    }

    @Test
    public void clientRegistrationIsAddedToOAuth2Request() throws NotFoundException, InvalidClientException {
        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        when(clientRegistrationStore.get(eq(CLIENT_ID), any(OAuth2Request.class))).thenReturn(clientRegistration);
        HttpRequest request = getRequest(CLIENT_ID);

        OAuth2Request oAuth2Request = factory.create(request);

        assertThat(oAuth2Request.getClientRegistration()).isEqualTo(clientRegistration);
    }

    @Test
    public void oAuth2RequestWithClientRegistrationIsAddedToHttpRequest()
            throws NotFoundException, InvalidClientException {
        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        when(clientRegistrationStore.get(eq(CLIENT_ID), any(OAuth2Request.class))).thenReturn(clientRegistration);
        HttpRequest request = getRequest(CLIENT_ID);

        factory.create(request);

        ArgumentCaptor<OAuth2Request> argument = ArgumentCaptor.forClass(OAuth2Request.class);
        verify(httpServletRequest, times(1)).setAttribute(eq("OAUTH2_REQ_ATTR"), argument.capture());
        assertThat(argument.getValue().getClientRegistration()).isEqualTo(clientRegistration);
    }

    @Test
    public void clientRegistrationIsNullWhenClientIdIsNotProvided() throws NotFoundException, InvalidClientException {
        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        when(clientRegistrationStore.get(eq(CLIENT_ID), any(OAuth2Request.class))).thenReturn(clientRegistration);
        HttpRequest request = getRequest(null);

        OAuth2Request oAuth2Request = factory.create(request);

        assertThat(oAuth2Request.getClientRegistration()).isNull();
    }

    @Test
    public void clientRegistrationIsNullWhenClientIdIsBlank() throws NotFoundException, InvalidClientException {
        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        when(clientRegistrationStore.get(eq(CLIENT_ID), any(OAuth2Request.class))).thenReturn(clientRegistration);
        HttpRequest request = getRequest("");

        OAuth2Request oAuth2Request = factory.create(request);

        assertThat(oAuth2Request.getClientRegistration()).isNull();
    }

    @Test
    public void clientRegistrationIsNullWhenStoreThrowsException() throws NotFoundException, InvalidClientException {
        doThrow(InvalidClientException.class).when(clientRegistrationStore).get(eq(CLIENT_ID), any(OAuth2Request.class));
        HttpRequest request = getRequest(null);

        OAuth2Request oAuth2Request = factory.create(request);

        assertThat(oAuth2Request.getClientRegistration()).isNull();
    }

    @Test
    public void chfRequestGetsItsClientRegistration() throws NotFoundException, InvalidClientException {
        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        when(clientRegistrationStore.get(eq(CLIENT_ID), any(OAuth2Request.class))).thenReturn(clientRegistration);
        AttributesContext context = new AttributesContext(new RootContext());

        OAuth2Request oAuth2Request = factory.create(context, chfRequest("client_id=" + CLIENT_ID));

        assertThat(oAuth2Request).isInstanceOf(ChfOAuth2Request.class);
        assertThat(oAuth2Request.getClientRegistration()).isEqualTo(clientRegistration);
    }

    @Test
    public void chfRequestIsCachedOnTheAttributesContext() throws NotFoundException, InvalidClientException {
        AttributesContext context = new AttributesContext(new RootContext());
        org.forgerock.http.protocol.Request request = chfRequest("client_id=" + CLIENT_ID);

        OAuth2Request first = factory.create(context, request);
        OAuth2Request second = factory.create(context, request);

        assertThat(second).isSameAs(first);
        assertThat(context.getAttributes().get("OAUTH2_REQ_ATTR")).isSameAs(first);
    }

    @Test
    public void chfClientRegistrationIsNullWhenClientIdIsNotProvided() throws NotFoundException, InvalidClientException {
        AttributesContext context = new AttributesContext(new RootContext());

        OAuth2Request oAuth2Request = factory.create(context, chfRequest(null));

        assertThat(oAuth2Request.getClientRegistration()).isNull();
        verify(clientRegistrationStore, never()).get(any(String.class), any(OAuth2Request.class));
    }

    private org.forgerock.http.protocol.Request chfRequest(String query) {
        org.forgerock.http.protocol.Request request = new org.forgerock.http.protocol.Request().setMethod("GET");
        try {
            request.setUri("http://openam.example.com:8080/openam/oauth2/authorize"
                    + (query == null ? "" : "?" + query));
        } catch (java.net.URISyntaxException e) {
            throw new IllegalStateException(e);
        }
        return request;
    }

    private HttpRequest getRequest(String clientId) {
        httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getParameter(OAuth2Constants.Params.CLIENT_ID)).thenReturn(clientId);

        ServletCall servletCall = mock(ServletCall.class);
        when(servletCall.getRequest()).thenReturn(httpServletRequest);

        HttpRequest request = mock(HttpRequest.class);
        when(request.getHttpCall()).thenReturn(servletCall);

        return request;
    }
}
