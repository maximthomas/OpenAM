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

package org.forgerock.oauth2.restlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.forgerock.http.protocol.Request;
import org.forgerock.oauth2.core.RestletOAuth2Request;
import org.forgerock.oauth2.core.exceptions.InvalidClientAuthZHeaderException;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.openidentityplatform.openam.oauth2.core.ChfOAuth2Request;
import org.restlet.data.ChallengeResponse;
import org.restlet.data.ChallengeScheme;
import org.restlet.data.Method;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Covers the choice this factory makes between a bare {@code invalid_client} error and one carrying a
 * {@code WWW-Authenticate} challenge, which turns on whether the request presented an authorization
 * header.
 *
 * <p>The Restlet cases pin the live path: they pass unchanged across the move from reading Restlet's
 * {@code ChallengeResponse} directly to reading the transport-neutral credentials accessor. The CHF
 * cases are the capability being added — before the change they fail, because the factory reached for
 * a Restlet request that a CHF-backed one cannot supply.
 */
public class OpenAMClientAuthenticationFailureFactoryTest {

    private static final String TOKEN_ENDPOINT = "http://openam.example.com:8080/openam/oauth2/access_token";

    /** {@literal Basic} credentials for {@literal myClient:secret}. */
    private static final String BASIC_HEADER = "Basic bXlDbGllbnQ6c2VjcmV0";

    private static final String MESSAGE = "Client authentication failed";

    private OpenAMClientAuthenticationFailureFactory factory;

    @BeforeMethod
    public void setUp() throws Exception {
        RealmNormaliser realmNormaliser = mock(RealmNormaliser.class);
        given(realmNormaliser.normalise(any())).willAnswer(invocation -> invocation.getArgument(0));
        factory = new OpenAMClientAuthenticationFailureFactory(realmNormaliser);
    }

    // --- CHF ----------------------------------------------------------------------------------

    @Test
    public void chfRequestWithABasicAuthorizationHeaderIsChallenged() throws Exception {
        Request request = new Request().setMethod("POST").setUri(TOKEN_ENDPOINT);
        request.getHeaders().put("Authorization", BASIC_HEADER);

        InvalidClientException exception = factory.getException(chf(request), MESSAGE);

        assertThat(exception).isInstanceOf(InvalidClientAuthZHeaderException.class);
        assertThat(((InvalidClientAuthZHeaderException) exception).getChallengeScheme()).isEqualTo("Basic");
    }

    @Test
    public void chfRequestWithoutAnAuthorizationHeaderIsNotChallenged() throws Exception {
        Request request = new Request().setMethod("POST").setUri(TOKEN_ENDPOINT);

        InvalidClientException exception = factory.getException(chf(request), MESSAGE);

        assertThat(exception).isNotInstanceOf(InvalidClientAuthZHeaderException.class);
    }

    /**
     * The header is detected by its presence, not by its scheme, matching Restlet — see
     * {@code BasicAuthHeader#parse}. The counterpart Restlet case below asserts the same.
     */
    @Test
    public void chfRequestWithANonBasicAuthorizationHeaderIsStillChallenged() throws Exception {
        Request request = new Request().setMethod("POST").setUri(TOKEN_ENDPOINT);
        request.getHeaders().put("Authorization", "Bearer f9063e26-3a29-41ec-86de-1d0d68aa85e9");

        assertThat(factory.getException(chf(request), MESSAGE))
                .isInstanceOf(InvalidClientAuthZHeaderException.class);
    }

    @Test
    public void chfChallengeCarriesTheNormalisedRealm() throws Exception {
        Request request = new Request().setMethod("POST").setUri(TOKEN_ENDPOINT + "?realm=/alpha");
        request.getHeaders().put("Authorization", BASIC_HEADER);

        InvalidClientException exception = factory.getException(chf(request), MESSAGE);

        assertThat(((InvalidClientAuthZHeaderException) exception).getChallengeRealm()).isEqualTo("/alpha");
    }

    // --- Restlet ------------------------------------------------------------------------------

    @Test
    public void restletRequestWithAChallengeResponseIsChallenged() {
        org.restlet.Request request = new org.restlet.Request(Method.POST, TOKEN_ENDPOINT);
        request.setChallengeResponse(new ChallengeResponse(ChallengeScheme.HTTP_BASIC, "myClient", "secret"));

        InvalidClientException exception = factory.getException(new RestletOAuth2Request(null, request), MESSAGE);

        assertThat(exception).isInstanceOf(InvalidClientAuthZHeaderException.class);
        assertThat(((InvalidClientAuthZHeaderException) exception).getChallengeScheme()).isEqualTo("Basic");
    }

    @Test
    public void restletRequestWithoutAChallengeResponseIsNotChallenged() {
        org.restlet.Request request = new org.restlet.Request(Method.POST, TOKEN_ENDPOINT);

        InvalidClientException exception = factory.getException(new RestletOAuth2Request(null, request), MESSAGE);

        assertThat(exception).isNotInstanceOf(InvalidClientAuthZHeaderException.class);
    }

    @Test
    public void restletRequestWithANonBasicChallengeResponseIsStillChallenged() {
        org.restlet.Request request = new org.restlet.Request(Method.POST, TOKEN_ENDPOINT);
        request.setChallengeResponse(new ChallengeResponse(ChallengeScheme.HTTP_OAUTH_BEARER));

        assertThat(factory.getException(new RestletOAuth2Request(null, request), MESSAGE))
                .isInstanceOf(InvalidClientAuthZHeaderException.class);
    }

    // --- shared -------------------------------------------------------------------------------

    @Test
    public void aNullRequestIsNotChallenged() {
        assertThat(factory.getException(null, MESSAGE)).isNotInstanceOf(InvalidClientAuthZHeaderException.class);
    }

    // --- helpers ------------------------------------------------------------------------------

    private ChfOAuth2Request chf(Request request) {
        return new ChfOAuth2Request(new RootContext(), request);
    }
}
