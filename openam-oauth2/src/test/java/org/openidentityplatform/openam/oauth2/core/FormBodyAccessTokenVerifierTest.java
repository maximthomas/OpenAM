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
import org.restlet.data.CharacterSet;
import org.restlet.data.MediaType;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.representation.StringRepresentation;
import org.testng.annotations.Test;

/**
 * Covers the form body access token verifier on both transports.
 *
 * <p>{@code UserInfoService} pairs this verifier with the header one and errors when both find a
 * token, so reading the wrong location would turn a rejected request into an accepted one.
 */
public class FormBodyAccessTokenVerifierTest {

    private static final String TOKEN = "f9063e26-3a29-41ec-86de-1d0d68aa85e9";
    private static final String BASE_URI = "http://openam.example.com:8080/openam/oauth2";
    private static final String FORM = "application/x-www-form-urlencoded";

    private final FormBodyAccessTokenVerifier verifier = new FormBodyAccessTokenVerifier(mock(TokenStore.class));

    // --- CHF ----------------------------------------------------------------------------------

    @Test
    public void chfReadsTheTokenFromAFormBody() throws Exception {
        assertThat(verifier.obtainTokenId(chf(postForm(FORM, "access_token=" + TOKEN)))).isEqualTo(TOKEN);
    }

    /**
     * CHF matches the whole {@code Content-Type} header unless the media type is parsed out, so a
     * charset parameter would silently yield an empty form.
     */
    @Test
    public void chfReadsTheTokenWhenTheContentTypeCarriesACharset() throws Exception {
        Request request = postForm(FORM + ";charset=UTF-8", "access_token=" + TOKEN);

        assertThat(verifier.obtainTokenId(chf(request))).isEqualTo(TOKEN);
    }

    @Test
    public void chfYieldsNullForAJsonBody() throws Exception {
        Request request = postForm("application/json", "{\"access_token\":\"" + TOKEN + "\"}");

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    @Test
    public void chfYieldsNullWhenTheFormHasNoAccessToken() throws Exception {
        assertThat(verifier.obtainTokenId(chf(postForm(FORM, "scope=openid")))).isNull();
    }

    @Test
    public void chfIgnoresATokenInTheQueryString() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/userinfo?access_token=" + TOKEN);

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    @Test
    public void chfIgnoresATokenInTheAuthorizationHeader() throws Exception {
        Request request = new Request().setMethod("GET").setUri(BASE_URI + "/userinfo");
        request.getHeaders().put("Authorization", "Bearer " + TOKEN);

        assertThat(verifier.obtainTokenId(chf(request))).isNull();
    }

    // --- Restlet ------------------------------------------------------------------------------

    @Test
    public void restletReadsTheTokenFromAFormBody() {
        org.restlet.Request request = new org.restlet.Request(Method.POST, BASE_URI + "/userinfo");
        request.setEntity(new StringRepresentation("access_token=" + TOKEN, MediaType.APPLICATION_WWW_FORM));

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, request))).isEqualTo(TOKEN);
    }

    /**
     * The Restlet counterpart of {@code chfReadsTheTokenWhenTheContentTypeCarriesACharset}, pinning
     * the transport parity for a charset-bearing {@code Content-Type}. Restlet's server adapter parses
     * the {@code charset} parameter out of the header into the representation's {@code CharacterSet},
     * leaving the {@code MediaType} clean, so {@code getFormParameter}'s
     * {@code MediaType.APPLICATION_WWW_FORM.equals(...)} guard still matches and the token is read —
     * exactly as the CHF path does once it parses the media type out.
     */
    @Test
    public void restletReadsTheTokenWhenTheContentTypeCarriesACharset() {
        org.restlet.Request request = new org.restlet.Request(Method.POST, BASE_URI + "/userinfo");
        StringRepresentation entity =
                new StringRepresentation("access_token=" + TOKEN, MediaType.APPLICATION_WWW_FORM);
        entity.setCharacterSet(CharacterSet.UTF_8);
        request.setEntity(entity);

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, request))).isEqualTo(TOKEN);
    }

    @Test
    public void restletYieldsNullForANonFormEntity() {
        org.restlet.Request request = new org.restlet.Request(Method.POST, BASE_URI + "/userinfo");
        request.setEntity(new StringRepresentation(
                "{\"access_token\":\"" + TOKEN + "\"}", MediaType.APPLICATION_JSON));

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, request))).isNull();
    }

    @Test
    public void restletYieldsNullWithoutAnEntity() {
        org.restlet.Request request = new org.restlet.Request(Method.GET, BASE_URI + "/userinfo");

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, request))).isNull();
    }

    @Test
    public void restletYieldsNullWhenTheFormHasNoAccessToken() {
        org.restlet.Request request = new org.restlet.Request(Method.POST, BASE_URI + "/userinfo");
        request.setEntity(new StringRepresentation("scope=openid", MediaType.APPLICATION_WWW_FORM));

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, request))).isNull();
    }

    @Test
    public void restletIgnoresATokenInTheQueryString() {
        String uri = BASE_URI + "/userinfo?access_token=" + TOKEN;
        org.restlet.Request request = new org.restlet.Request(Method.GET, uri);
        request.setOriginalRef(new Reference(uri));

        assertThat(verifier.obtainTokenId(new RestletOAuth2Request(null, request))).isNull();
    }

    // --- helpers ------------------------------------------------------------------------------

    private ChfOAuth2Request chf(Request request) {
        return new ChfOAuth2Request(new RootContext(), request);
    }

    private Request postForm(String contentType, String body) throws Exception {
        Request request = new Request().setMethod("POST").setUri(BASE_URI + "/userinfo");
        request.getHeaders().put("Content-Type", contentType);
        request.getEntity().setString(body);
        return request;
    }
}
