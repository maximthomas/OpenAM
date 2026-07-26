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

package org.forgerock.oauth2.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.forgerock.openam.oauth2.OAuth2Constants.EndpointType;
import org.forgerock.openam.rest.service.RestletRealmRouter;
import org.openidentityplatform.openam.oauth2.core.BasicAuthHeader;
import org.restlet.Request;
import org.restlet.data.ChallengeResponse;
import org.restlet.data.ChallengeScheme;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.testng.annotations.Test;

/**
 * Covers the transport-neutral accessors of the Restlet-backed request, which the shared OAuth2
 * collaborators now depend on.
 */
public class RestletOAuth2RequestTest {

    private static final String BASE_URI = "http://openam.example.com:8080/openam/oauth2";

    // --- endpoint path ----------------------------------------------------------------------

    @Test
    public void endpointPathIsResolvedForAnUnprefixedUri() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/access_token");

        assertThat(request.getEndpointPath()).isEqualTo("/access_token");
        assertThat(request.getEndpointType()).isEqualTo(EndpointType.TOKEN_ENDPOINT);
    }

    /**
     * The realm router leaves {@literal realmUrl} pointing at the {@literal /oauth2} base, so the
     * {@literal /realms/{realm}} segments have to be stripped before the endpoint can be recognised.
     */
    @Test
    public void endpointPathIsResolvedForARealmPrefixedUri() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/realms/root/access_token");

        assertThat(request.getEndpointPath()).isEqualTo("/access_token");
        assertThat(request.getEndpointType()).isNotNull().isEqualTo(EndpointType.TOKEN_ENDPOINT);
    }

    @Test
    public void endpointPathIsResolvedForANestedRealmPrefixedUri() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/realms/root/realms/sub/authorize");

        assertThat(request.getEndpointType()).isEqualTo(EndpointType.AUTHORIZATION_ENDPOINT);
    }

    @Test
    public void endpointPathIsResolvedForAMultiSegmentEndpoint() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/realms/root/device/user");

        assertThat(request.getEndpointType()).isEqualTo(EndpointType.END_USER_VERIFICATION_URI);
    }

    @Test
    public void endpointPathIsNullWithoutTheRealmUrlAttribute() {
        Request restletRequest = new Request(Method.GET, BASE_URI + "/access_token");

        RestletOAuth2Request request = new RestletOAuth2Request(null, restletRequest);

        assertThat(request.getEndpointPath()).isNull();
        assertThat(request.getEndpointType()).isNull();
    }

    @Test
    public void unknownEndpointHasNoType() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/realms/root/resource_set/abc");

        assertThat(request.getEndpointPath()).isEqualTo("/resource_set/abc");
        assertThat(request.getEndpointType()).isNull();
    }

    // --- request URL mutation ---------------------------------------------------------------

    @Test
    public void setQueryParameterAddsAMissingParameter() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/authorize?client_id=one");

        request.setQueryParameter("max_age", "-1");

        assertThat(request.getRequestUrl()).isEqualTo(BASE_URI + "/authorize?client_id=one&max_age=-1");
        assertThat(request.<String>getParameter("max_age")).isEqualTo("-1");
    }

    @Test
    public void setQueryParameterReplacesAnExistingValue() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/authorize?max_age=30&client_id=one");

        request.setQueryParameter("max_age", "-1");

        assertThat(request.getRequestUrl()).isEqualTo(BASE_URI + "/authorize?max_age=-1&client_id=one");
    }

    /**
     * {@code getQueryParameter} is deliberately <em>not</em> the read companion to
     * {@code setQueryParameter}: it reads the original reference while the setter writes the resource
     * reference, so a write is invisible to it. The counterpart CHF test asserts the opposite, because
     * both of its operations go through the request URI. The asymmetry is accepted rather than fixed —
     * reading the original reference is what the query access token verifier has always done — so it is
     * pinned here to keep it a documented contract rather than a surprise.
     */
    @Test
    public void getQueryParameterDoesNotSeeASetQueryParameterWrite() {
        String uri = BASE_URI + "/authorize?max_age=30";
        Request restletRequest = new Request(Method.GET, uri);
        restletRequest.setResourceRef(new Reference(uri));
        restletRequest.setOriginalRef(new Reference(uri));
        RestletOAuth2Request request = new RestletOAuth2Request(null, restletRequest);

        request.setQueryParameter("max_age", "-1");

        assertThat(request.getRequestUrl()).isEqualTo(BASE_URI + "/authorize?max_age=-1");
        assertThat(request.getQueryParameter("max_age")).isEqualTo("30");
    }

    @Test
    public void removeQueryParameterValueStripsTheValueButKeepsTheParameter() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/authorize?prompt=login%20consent");

        request.removeQueryParameterValue("prompt", "login");

        assertThat(request.<String>getParameter("prompt")).isEqualTo("consent");
    }

    @Test
    public void removeQueryParameterValueLeavesAnEmptyValueWhenNothingRemains() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/authorize?prompt=login");

        request.removeQueryParameterValue("prompt", "login");

        assertThat(request.getRequestUrl()).isEqualTo(BASE_URI + "/authorize?prompt=");
    }

    // --- attributes and authorization --------------------------------------------------------

    @Test
    public void attributesAreWritableAndReadBack() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/authorize");

        request.setAttribute("acr", "2");

        assertThat(request.getAttribute("acr")).isEqualTo("2");
        assertThat(request.<String>getParameter("acr")).isEqualTo("2");
    }

    @Test
    public void basicAuthCredentialsComeFromTheChallengeResponse() {
        Request restletRequest = new Request(Method.GET, BASE_URI + "/access_token");
        restletRequest.setChallengeResponse(
                new ChallengeResponse(ChallengeScheme.HTTP_BASIC, "myClient", "secret"));

        RestletOAuth2Request request = new RestletOAuth2Request(null, restletRequest);

        BasicAuthHeader credentials = request.getBasicAuthCredentials();
        assertThat(credentials.getClientId()).isEqualTo("myClient");
        assertThat(credentials.getSecret()).isEqualTo("secret".toCharArray());
    }

    @Test
    public void basicAuthCredentialsAreNullWithoutAChallengeResponse() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/access_token");

        assertThat(request.getBasicAuthCredentials()).isNull();
    }

    /**
     * Restlet parses a challenge response for every scheme, and the client authentication relies on
     * its presence to detect a request carrying two authentication methods.
     */
    /**
     * The transports diverge here, and the divergence is accepted. Restlet falls back to the parsed
     * challenge response for any non-Bearer scheme, so a Basic header yields its raw credential blob;
     * the CHF counterpart returns {@code null}. This is unobservable at the {@code verify()} boundary —
     * a credential blob is not a token id, so it fails token lookup exactly as a {@code null} does —
     * but it is pinned so that the Phase 5 port does not "unify" the two by accident.
     */
    @Test
    public void aNonBearerSchemeFallsBackToTheChallengeResponseRawValue() {
        Request restletRequest = new Request(Method.GET, BASE_URI + "/userinfo");
        ChallengeResponse challengeResponse = new ChallengeResponse(ChallengeScheme.HTTP_BASIC);
        challengeResponse.setRawValue("dXNlcjpwYXNz");
        restletRequest.setChallengeResponse(challengeResponse);

        RestletOAuth2Request request = new RestletOAuth2Request(null, restletRequest);

        assertThat(request.getAuthorizationBearerToken()).isEqualTo("dXNlcjpwYXNz");
    }

    @Test
    public void aNonBasicChallengeResponseStillYieldsCredentials() {
        Request restletRequest = new Request(Method.GET, BASE_URI + "/access_token");
        restletRequest.setChallengeResponse(new ChallengeResponse(ChallengeScheme.HTTP_OAUTH_BEARER));

        RestletOAuth2Request request = new RestletOAuth2Request(null, restletRequest);

        assertThat(request.getBasicAuthCredentials()).isNotNull();
        assertThat(request.getBasicAuthCredentials().getClientId()).isNull();
    }

    /**
     * {@code RestletOAuth2Request} is the one subclass that does not override
     * {@link OAuth2Request#getAcceptedLanguages()} -- correctly, since the Restlet resources read
     * {@code ClientInfo} directly and never call it. This pins what it inherits: the wildcard, which is what
     * S4 proved an absent {@code Accept-Language} produces on the wire. The empty list it used to inherit
     * would render {@code locale: ""} into the consent page if a shared collaborator were ever handed a
     * Restlet-backed request -- a value no live request has ever produced.
     */
    @Test
    public void theInheritedAcceptedLanguagesAreTheWildcardNotAnEmptyList() {
        RestletOAuth2Request request = restletRequest(BASE_URI + "/authorize");

        assertThat(request.getAcceptedLanguages()).containsExactly("*");
    }

    // --- helpers ------------------------------------------------------------------------------

    /** Builds a request routed as the Restlet realm router leaves it: {@code realmUrl} is the OAuth2 base. */
    private RestletOAuth2Request restletRequest(String uri) {
        Request restletRequest = new Request(Method.GET, uri);
        restletRequest.setResourceRef(new Reference(uri));
        restletRequest.getAttributes().put(RestletRealmRouter.REALM_URL, BASE_URI);
        return new RestletOAuth2Request(null, restletRequest);
    }
}
