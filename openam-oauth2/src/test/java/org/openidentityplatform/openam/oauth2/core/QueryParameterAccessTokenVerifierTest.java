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
import static org.mockito.Mockito.mock;

import org.forgerock.http.protocol.Request;
import org.forgerock.oauth2.core.RestletOAuth2Request;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.services.context.RootContext;
import org.restlet.data.MediaType;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.representation.StringRepresentation;
import org.testng.annotations.Test;

/**
 * Covers the query parameter access token verifier on both transports.
 *
 * <p>{@code TokenInfoService} pairs this verifier with the header one and errors when both find a
 * token, so reading the wrong location would turn a rejected request into an accepted one.
 */
public class QueryParameterAccessTokenVerifierTest {

    private static final String TOKEN = "f9063e26-3a29-41ec-86de-1d0d68aa85e9";
    private static final String BASE_URI = "http://openam.example.com:8080/openam/oauth2";

    private final QueryParameterAccessTokenVerifier verifier =
            new QueryParameterAccessTokenVerifier(mock(TokenStore.class));

    // --- CHF ----------------------------------------------------------------------------------

    @Test
    public void chfReadsTheTokenFromTheQueryString() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/tokeninfo?access_token=" + TOKEN);

        assertThat(verifier.obtainTokenId(chf(request))).isEqualTo(TOKEN);
    }

    @Test
    public void chfYieldsNullWithoutAQueryString() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/tokeninfo");

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    @Test
    public void chfYieldsNullWhenTheQueryHasNoAccessToken() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/tokeninfo?scope=openid");

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    @Test
    public void chfIgnoresATokenInTheAuthorizationHeader() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/tokeninfo");
        request.getHeaders().put("Authorization", "Bearer " + TOKEN);

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    @Test
    public void chfIgnoresATokenInTheFormBody() throws Exception {
        Request request = new Request().setMethod("POST").setUri(BASE_URI + "/tokeninfo");
        request.getHeaders().put("Content-Type", "application/x-www-form-urlencoded");
        request.getEntity().setString("access_token=" + TOKEN);

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    // --- Restlet ------------------------------------------------------------------------------

    @Test
    public void restletReadsTheTokenFromTheQueryString() {
        assertThat(verifier.obtainTokenId(restletRequest("?access_token=" + TOKEN))).isEqualTo(TOKEN);
    }

    @Test
    public void restletYieldsNullWithoutAQueryString() {
        assertThat(verifier.obtainTokenId(restletRequest(""))).isNull();
    }

    @Test
    public void restletYieldsNullWhenTheQueryHasNoAccessToken() {
        assertThat(verifier.obtainTokenId(restletRequest("?scope=openid"))).isNull();
    }

    /**
     * Pins the source: the token is read from the <em>original</em> reference, not the resource
     * reference the routers rewrite. The two are distinct objects on a dispatched request, and the
     * verifier has always read the original one.
     */
    @Test
    public void restletReadsTheOriginalReferenceRatherThanTheResourceReference() {
        org.restlet.Request request = new org.restlet.Request(Method.GET, BASE_URI + "/tokeninfo");
        request.setOriginalRef(new Reference(BASE_URI + "/tokeninfo?access_token=" + TOKEN));
        request.setResourceRef(new Reference(BASE_URI + "/tokeninfo"));

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, request))).isEqualTo(TOKEN);
    }

    @Test
    public void restletIgnoresATokenInTheFormBody() {
        org.restlet.Request request = new org.restlet.Request(Method.POST, BASE_URI + "/tokeninfo");
        request.setOriginalRef(new Reference(BASE_URI + "/tokeninfo"));
        request.setEntity(new StringRepresentation("access_token=" + TOKEN, MediaType.APPLICATION_WWW_FORM));

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, request))).isNull();
    }

    // --- helpers ------------------------------------------------------------------------------

    private ChfOAuth2Request chf(Request request) {
        return new ChfOAuth2Request(new RootContext(), request);
    }

    /**
     * Restlet's server adapter populates the original reference under real dispatch; a plainly
     * constructed request has to be given one explicitly.
     */
    private RestletOAuth2Request restletRequest(String query) {
        String uri = BASE_URI + "/tokeninfo" + query;
        org.restlet.Request request = new org.restlet.Request(Method.GET, uri);
        request.setOriginalRef(new Reference(uri));
        return new RestletOAuth2Request(null, request);
    }
}
