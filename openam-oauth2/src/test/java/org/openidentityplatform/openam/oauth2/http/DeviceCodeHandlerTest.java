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
package org.openidentityplatform.openam.oauth2.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.DeviceCode;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2Utils;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link DeviceCodeHandler} ({@code /device/code}). POST only. Pins the success map keys, the
 * {@code bad_request} (not {@code invalid_request}) 400 on missing required params, and the {@code verification_uri}
 * fallback via the <em>configured</em> base-URL provider (finding 5, deliberately not the raw reconstruction). No
 * cache headers.
 */
public class DeviceCodeHandlerTest {

    private OAuth2RequestFactory requestFactory;
    private TokenStore tokenStore;
    private ClientRegistrationStore clientRegistrationStore;
    private OAuth2ProviderSettingsFactory providerSettingsFactory;
    private BaseURLProviderFactory baseURLProviderFactory;
    private OAuth2ProviderSettings providerSettings;
    private OAuth2Request o2;
    private DeviceCodeHandler handler;

    @BeforeMethod
    public void setup() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        tokenStore = mock(TokenStore.class);
        clientRegistrationStore = mock(ClientRegistrationStore.class);
        providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        baseURLProviderFactory = mock(BaseURLProviderFactory.class);
        providerSettings = mock(OAuth2ProviderSettings.class);
        o2 = mock(OAuth2Request.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);
        when(providerSettingsFactory.get(o2)).thenReturn(providerSettings);

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new DeviceCodeHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "tokenStore", tokenStore);
        inject(handler, "clientRegistrationStore", clientRegistrationStore);
        inject(handler, "providerSettingsFactory", providerSettingsFactory);
        inject(handler, "baseURLProviderFactory", baseURLProviderFactory);
        inject(handler, "oAuth2Utils", new OAuth2Utils());   // real: exercises the actual scope split
    }

    // --- success ----------------------------------------------------------------------------------

    @Test
    public void postIssuesDeviceCodeWith200AndConfiguredVerificationUrl() throws Exception {
        stubRequiredParams("myclient", "openid profile", "code");
        stubCreatedCode("dcode", "ucode");
        when(providerSettings.getDeviceCodeLifetime()).thenReturn(300);
        when(providerSettings.getDeviceCodePollInterval()).thenReturn(5);
        when(providerSettings.getVerificationUrl()).thenReturn("https://configured.example/device");

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();
        Map<String, Object> body = bodyOf(response);
        assertThat(body).containsEntry("device_code", "dcode")
                .containsEntry("user_code", "ucode")
                .containsEntry("verification_uri", "https://configured.example/device");
        assertThat(((Number) body.get("expires_in")).intValue()).isEqualTo(300);
        assertThat(((Number) body.get("interval")).intValue()).isEqualTo(5);
    }

    /** No configured verification URL -> fall back to the configured base-URL provider + {@code /oauth2/device/user}. */
    @Test
    public void postFallsBackToBaseUrlProviderVerificationUrl() throws Exception {
        stubRequiredParams("myclient", "openid", "code");
        stubCreatedCode("dcode", "ucode");
        when(providerSettings.getDeviceCodeLifetime()).thenReturn(300);
        when(providerSettings.getDeviceCodePollInterval()).thenReturn(5);
        when(providerSettings.getVerificationUrl()).thenReturn("");   // blank -> fallback

        when(o2.<String>getParameter(OAuth2Constants.Custom.REALM)).thenReturn("/myrealm");
        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(o2.getHttpServletRequest()).thenReturn(servletRequest);
        BaseURLProvider baseUrlProvider = mock(BaseURLProvider.class);
        when(baseURLProviderFactory.get("/myrealm")).thenReturn(baseUrlProvider);
        when(baseUrlProvider.getRootURL(servletRequest)).thenReturn("https://host/openam");

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).containsEntry("verification_uri", "https://host/openam/oauth2/device/user");
    }

    /** A supplied max_age is parsed to an Integer (not passed as a String) and threaded to createDeviceCode. */
    @Test
    public void suppliedMaxAgeIsParsedToInteger() throws Exception {
        stubRequiredParams("myclient", "openid", "code");
        stubCreatedCode("dcode", "ucode");
        when(providerSettings.getVerificationUrl()).thenReturn("https://configured.example/device");
        when(o2.<String>getParameter(OAuth2Constants.Params.MAX_AGE)).thenReturn("90");

        dispatch();

        ArgumentCaptor<Integer> maxAge = ArgumentCaptor.forClass(Integer.class);
        verify(tokenStore).createDeviceCode(any(), any(), any(), any(), any(), any(), any(), any(),
                any(), any(), maxAge.capture(), any(), any(), any(), any());
        assertThat(maxAge.getValue()).isEqualTo(90);
    }

    // --- errors -----------------------------------------------------------------------------------

    /** Missing any of client_id/scope/response_type -> 400 bad_request (byte-parity, NOT invalid_request). */
    @Test
    public void missingRequiredParamsReturns400BadRequest() throws Exception {
        stubRequiredParams("myclient", null, "code");   // scope missing

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "bad_request");
    }

    /** The client-existence check is wired: its exception propagates to the base JSON error mapper. */
    @Test
    public void unknownClientPropagatesToJsonError() throws Exception {
        stubRequiredParams("ghost", "openid", "code");
        when(clientRegistrationStore.get("ghost", o2)).thenThrow(new NotFoundException("no such realm"));

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(404);
        assertThat(bodyOf(response)).containsEntry("error", "not_found");
    }

    // --- helpers ----------------------------------------------------------------------------------

    private void stubRequiredParams(String clientId, String scope, String responseType) {
        when(o2.<String>getParameter(OAuth2Constants.Params.CLIENT_ID)).thenReturn(clientId);
        when(o2.<String>getParameter(OAuth2Constants.Params.SCOPE)).thenReturn(scope);
        when(o2.<String>getParameter(OAuth2Constants.Params.RESPONSE_TYPE)).thenReturn(responseType);
    }

    private void stubCreatedCode(String deviceCode, String userCode) throws Exception {
        DeviceCode code = mock(DeviceCode.class);
        when(code.getDeviceCode()).thenReturn(deviceCode);
        when(code.getUserCode()).thenReturn(userCode);
        when(tokenStore.createDeviceCode(any(), any(), any(), any(), any(), any(), any(), any(),
                any(), any(), any(), any(), any(), any(), any())).thenReturn(code);
    }

    private Response dispatch() throws Exception {
        Request request = new Request().setMethod("POST");
        return Endpoints.from(handler).handle(new RootContext(), request).getOrThrowUninterruptibly();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    private static void inject(Object target, String name, Object value) throws Exception {
        for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException keepWalking) {
                // field is declared on a superclass
            }
        }
        throw new NoSuchFieldException(name);
    }
}
