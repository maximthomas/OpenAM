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
package org.openidentityplatform.openam.oauth2.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.forgerock.http.protocol.Request;
import org.forgerock.oauth2.core.RestletOAuth2Request;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.services.context.RootContext;
import org.restlet.data.ChallengeResponse;
import org.restlet.data.ChallengeScheme;
import org.restlet.data.Header;
import org.restlet.data.MediaType;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.engine.adapter.HttpRequest;
import org.restlet.engine.adapter.ServerCall;
import org.restlet.engine.header.HeaderConstants;
import org.restlet.representation.StringRepresentation;
import org.restlet.util.Series;
import org.testng.annotations.Test;

/**
 * Covers the header access token verifier on both transports.
 *
 * <p>The token location is load-bearing: {@code UserInfoService} pairs this verifier with the form
 * body one and errors when both find a token, so a verifier that read the wrong location would turn
 * a rejected request into an accepted one. Hence the "wrong location yields null" cases.
 */
public class HeaderAccessTokenVerifierTest {

    private static final String TOKEN = "f9063e26-3a29-41ec-86de-1d0d68aa85e9";
    private static final String BASE_URI = "http://openam.example.com:8080/openam/oauth2";

    private final HeaderAccessTokenVerifier verifier = new HeaderAccessTokenVerifier(mock(TokenStore.class));

    // --- CHF ----------------------------------------------------------------------------------

    @Test
    public void chfReadsTheBearerToken() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/userinfo");
        request.getHeaders().put("Authorization", "Bearer " + TOKEN);

        assertThat(verifier.obtainTokenId(chf(request))).isEqualTo(TOKEN);
    }

    @Test
    public void chfYieldsNullWithoutAnAuthorizationHeader() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/userinfo");

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    @Test
    public void chfYieldsNullForANonBearerScheme() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/userinfo");
        request.getHeaders().put("Authorization", "Basic dXNlcjpwYXNz");

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    @Test
    public void chfIgnoresATokenInTheQueryString() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/userinfo?access_token=" + TOKEN);

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    @Test
    public void chfIgnoresATokenInTheFormBody() throws Exception {
        Request request = new Request().setMethod("POST").setUri(BASE_URI + "/userinfo");
        request.getHeaders().put("Content-Type", "application/x-www-form-urlencoded");
        request.getEntity().setString("access_token=" + TOKEN);

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    // --- Restlet ------------------------------------------------------------------------------

    /**
     * The raw {@code Authorization} header is only readable through Restlet's server adapter, so this
     * is the one path a plainly constructed {@code Request} cannot reach — a test that built one and
     * asserted {@code null} would pass while proving nothing. Mocking the engine internal is the only
     * way to execute the Bearer parse below real HTTP dispatch.
     */
    @Test
    public void restletParsesTheBearerTokenFromTheRawHeader() {
        RestletOAuth2Request request = dispatchedRestletRequest("Bearer " + TOKEN);

        assertThat(verifier.obtainTokenId(request)).isEqualTo(TOKEN);
    }

    @Test
    public void restletBearerParseIsCaseInsensitiveOnTheScheme() {
        RestletOAuth2Request request = dispatchedRestletRequest("bEaReR " + TOKEN);

        assertThat(verifier.obtainTokenId(request)).isEqualTo(TOKEN);
    }

    @Test
    public void restletYieldsNullWhenTheDispatchedRequestHasNoAuthorizationHeader() {
        RestletOAuth2Request request = dispatchedRestletRequest(null);

        assertThat(verifier.obtainTokenId(request)).isNull();
    }

    /**
     * A {@code ChallengeResponse} set programmatically rather than parsed from a raw header — the shape
     * openam-uma builds — is reachable only through the fallback, since the request is not an
     * {@code HttpRequest}.
     */
    @Test
    public void restletFallsBackToAProgrammaticChallengeResponse() {
        org.restlet.Request restletRequest = new org.restlet.Request(Method.GET, BASE_URI + "/userinfo");
        ChallengeResponse challengeResponse =
                new ChallengeResponse(new ChallengeScheme("HTTP_Bearer", "Bearer"));
        challengeResponse.setRawValue(TOKEN);
        restletRequest.setChallengeResponse(challengeResponse);

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, restletRequest))).isEqualTo(TOKEN);
    }

    @Test
    public void restletYieldsNullWithoutAChallengeResponse() {
        org.restlet.Request restletRequest = new org.restlet.Request(Method.GET, BASE_URI + "/userinfo");

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, restletRequest))).isNull();
    }

    @Test
    public void restletIgnoresATokenInTheQueryString() {
        String uri = BASE_URI + "/userinfo?access_token=" + TOKEN;
        org.restlet.Request restletRequest = new org.restlet.Request(Method.GET, uri);
        restletRequest.setOriginalRef(new Reference(uri));

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, restletRequest))).isNull();
    }

    @Test
    public void restletIgnoresATokenInTheFormBody() {
        org.restlet.Request restletRequest = new org.restlet.Request(Method.POST, BASE_URI + "/userinfo");
        restletRequest.setEntity(
                new StringRepresentation("access_token=" + TOKEN, MediaType.APPLICATION_WWW_FORM));

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, restletRequest))).isNull();
    }

    // --- helpers ------------------------------------------------------------------------------

    private ChfOAuth2Request chf(Request request) {
        return new ChfOAuth2Request(new RootContext(), request);
    }

    /**
     * Builds the one request shape that reaches the Bearer parse: an {@code HttpRequest}, as Restlet's
     * server adapter produces under real dispatch, carrying the given raw {@code Authorization} header.
     */
    private RestletOAuth2Request dispatchedRestletRequest(String authorizationHeader) {
        Series<Header> headers = new Series<>(Header.class);
        if (authorizationHeader != null) {
            headers.add(new Header(HeaderConstants.HEADER_AUTHORIZATION, authorizationHeader));
        }
        ServerCall httpCall = mock(ServerCall.class);
        given(httpCall.getRequestHeaders()).willReturn(headers);
        HttpRequest httpRequest = mock(HttpRequest.class);
        given(httpRequest.getHttpCall()).willReturn(httpCall);

        return new RestletOAuth2Request(null, httpRequest);
    }
}
