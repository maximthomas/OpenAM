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

import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.routing.UriRouterContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.oauth2.OAuth2Constants.EndpointType;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class ChfOAuth2RequestTest {

    private static final String FORM = "application/x-www-form-urlencoded";
    private static final String FORM_WITH_CHARSET = "application/x-www-form-urlencoded;charset=UTF-8";
    private static final String JSON_WITH_CHARSET = "application/json;charset=UTF-8";
    private static final String DEPLOYMENT_URI = "http://openam.example.com:8080/openam";
    private static final String BASE_URI = DEPLOYMENT_URI + "/oauth2";

    private RealmTestHelper realmTestHelper;
    private AttributesContext attributesContext;

    @BeforeMethod
    public void setUp() throws Exception {
        realmTestHelper = new RealmTestHelper();
        realmTestHelper.setupRealmClass();
        attributesContext = new AttributesContext(new RootContext());
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
    }

    // --- parameter precedence --------------------------------------------------------------

    @Test
    public void attributeTakesPrecedenceOverQueryParameter() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize?rsid=fromQuery"),
                endpointContext("authorize", singletonMap("rsid", "fromTemplate")));

        assertThat(request.<String>getParameter("rsid")).isEqualTo("fromTemplate");
    }

    @Test
    public void realmIsExposedAsAnAttribute() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize"), endpointContext("authorize", emptyMap()));

        assertThat(request.<String>getParameter("realm")).isEqualTo(Realm.root().asPath());
    }

    @Test
    public void queryParameterTakesPrecedenceOverFormBody() throws Exception {
        Request httpRequest = post("/oauth2/access_token?code=fromQuery", FORM, "code=fromBody");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        assertThat(request.<String>getParameter("code")).isEqualTo("fromQuery");
    }

    @Test
    public void readsFormBodyWhenContentTypeCarriesACharset() throws Exception {
        Request httpRequest = post("/oauth2/access_token", FORM_WITH_CHARSET, "code=abc&grant_type=authorization_code");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        assertThat(request.<String>getParameter("code")).isEqualTo("abc");
        assertThat(request.<String>getParameter("grant_type")).isEqualTo("authorization_code");
    }

    @Test
    public void readsJsonBodyWhenContentTypeCarriesACharset() throws Exception {
        Request httpRequest = post("/oauth2/access_token", JSON_WITH_CHARSET, "{\"code\":\"abc\"}");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        assertThat(request.<String>getParameter("code")).isEqualTo("abc");
    }

    @Test
    public void formBodyCanBeReadRepeatedly() throws Exception {
        Request httpRequest = post("/oauth2/access_token", FORM, "code=abc");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        assertThat(request.<String>getParameter("code")).isEqualTo("abc");
        assertThat(request.<String>getParameter("code")).isEqualTo("abc");
        assertThat(request.getParameterNames()).containsOnly("code");
    }

    @Test
    public void jsonBodyCanBeReadRepeatedly() throws Exception {
        Request httpRequest = post("/oauth2/access_token", JSON_WITH_CHARSET, "{\"code\":\"abc\"}");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        assertThat(request.getBody().get("code").asString()).isEqualTo("abc");
        assertThat(request.getBody().get("code").asString()).isEqualTo("abc");
    }

    @Test
    public void unknownParameterIsNull() throws Exception {
        Request httpRequest = post("/oauth2/access_token", FORM, "code=abc");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        assertThat(request.<String>getParameter("state")).isNull();
    }

    // --- parameter count / names -----------------------------------------------------------

    @Test
    public void parameterCountCountsQueryStringDuplicatesOnly() throws Exception {
        Request httpRequest = post("/oauth2/access_token?scope=a&scope=b", FORM, "scope=c");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        assertThat(request.getParameterCount("scope")).isEqualTo(2);
        assertThat(request.getParameterCount("absent")).isEqualTo(0);
    }

    @Test
    public void parameterNamesOfGetComeFromTheQueryString() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize?client_id=one&state=two"),
                endpointContext("authorize", emptyMap()));

        assertThat(request.getParameterNames()).containsOnly("client_id", "state");
    }

    @Test
    public void parameterNamesOfJsonPostComeFromTheBody() throws Exception {
        Request httpRequest = post("/oauth2/access_token", JSON_WITH_CHARSET, "{\"code\":\"abc\",\"state\":\"s\"}");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        assertThat(request.getParameterNames()).containsOnly("code", "state");
    }

    @Test
    public void parameterNamesIsEmptyForAnUnsupportedMediaType() throws Exception {
        Request httpRequest = post("/oauth2/access_token", "text/plain", "code=abc");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        assertThat(request.getParameterNames()).isEmpty();
    }

    // --- endpoint type ---------------------------------------------------------------------

    @Test
    public void endpointTypeIsResolvedForARealmPrefixedUri() throws Exception {
        Request httpRequest = get("/oauth2/realms/root/access_token");

        ChfOAuth2Request request = chfRequest(httpRequest, realmPrefixedEndpointContext("access_token"));

        assertThat(request.getEndpointPath()).isEqualTo("/access_token");
        assertThat(request.getEndpointType()).isNotNull().isEqualTo(EndpointType.TOKEN_ENDPOINT);
    }

    @Test
    public void endpointTypeIsResolvedForAnUnprefixedUri() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/access_token"),
                endpointContext("access_token", emptyMap()));

        assertThat(request.getEndpointType()).isEqualTo(EndpointType.TOKEN_ENDPOINT);
    }

    @Test
    public void endpointTypeIsResolvedForAMultiSegmentEndpoint() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/device/user"),
                endpointContext("device/user", emptyMap()));

        assertThat(request.getEndpointType()).isEqualTo(EndpointType.END_USER_VERIFICATION_URI);
    }

    @Test
    public void endpointTypeIsNullWithoutARealmContext() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/access_token"),
                new UriRouterContext(attributesContext, "access_token", "", emptyMap()));

        assertThat(request.getEndpointPath()).isNull();
        assertThat(request.getEndpointType()).isNull();
    }

    // --- request URL mutation ---------------------------------------------------------------

    @Test
    public void setQueryParameterAddsAMissingParameter() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize?client_id=one"),
                endpointContext("authorize", emptyMap()));

        request.setQueryParameter("max_age", "-1");

        assertThat(request.getRequestUrl()).isEqualTo(BASE_URI + "/authorize?client_id=one&max_age=-1");
        assertThat(request.<String>getParameter("max_age")).isEqualTo("-1");
    }

    @Test
    public void setQueryParameterReplacesAnExistingValue() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize?max_age=30&client_id=one"),
                endpointContext("authorize", emptyMap()));

        request.setQueryParameter("max_age", "-1");

        assertThat(request.getRequestUrl()).isEqualTo(BASE_URI + "/authorize?max_age=-1&client_id=one");
    }

    /**
     * The counterpart of {@code RestletOAuth2RequestTest#getQueryParameterDoesNotSeeASetQueryParameterWrite},
     * asserting the opposite: here both the setter and the getter go through the request URI, so a write
     * <em>is</em> visible. The transports genuinely differ, and both behaviours are pinned so the
     * divergence stays deliberate.
     */
    @Test
    public void getQueryParameterSeesASetQueryParameterWrite() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize?max_age=30"),
                endpointContext("authorize", emptyMap()));

        request.setQueryParameter("max_age", "-1");

        assertThat(request.getRequestUrl()).isEqualTo(BASE_URI + "/authorize?max_age=-1");
        assertThat(request.getQueryParameter("max_age")).isEqualTo("-1");
    }

    @Test
    public void removeQueryParameterValueStripsTheValueButKeepsTheParameter() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize?prompt=login%20consent"),
                endpointContext("authorize", emptyMap()));

        request.removeQueryParameterValue("prompt", "login");

        assertThat(request.getRequestUrl()).isEqualTo(BASE_URI + "/authorize?prompt=consent");
        assertThat(request.<String>getParameter("prompt")).isEqualTo("consent");
    }

    @Test
    public void removeQueryParameterValueLeavesAnEmptyValueWhenNothingRemains() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize?prompt=login"),
                endpointContext("authorize", emptyMap()));

        request.removeQueryParameterValue("prompt", "login");

        assertThat(request.getRequestUrl()).isEqualTo(BASE_URI + "/authorize?prompt=");
    }

    // --- authorization header ---------------------------------------------------------------

    @Test
    public void basicAuthCredentialsAreDecodedAsIso88591() throws Exception {
        String secret = "sécrêt";
        String encoded = Base64.getEncoder().encodeToString(("myClient:" + secret).getBytes(StandardCharsets.ISO_8859_1));
        Request httpRequest = get("/oauth2/access_token");
        httpRequest.getHeaders().put("Authorization", "Basic " + encoded);

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        BasicAuthHeader credentials = request.getBasicAuthCredentials();
        assertThat(credentials.getClientId()).isEqualTo("myClient");
        assertThat(credentials.getSecret()).isEqualTo(secret.toCharArray());
    }

    @Test
    public void basicAuthCredentialsAreNullWithoutAnAuthorizationHeader() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/access_token"),
                endpointContext("access_token", emptyMap()));

        assertThat(request.getBasicAuthCredentials()).isNull();
    }

    @Test
    public void aNonBasicAuthorizationHeaderStillYieldsCredentialsWithoutAClientId() throws Exception {
        Request httpRequest = get("/oauth2/access_token");
        httpRequest.getHeaders().put("Authorization", "Bearer some-token");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("access_token", emptyMap()));

        BasicAuthHeader credentials = request.getBasicAuthCredentials();
        assertThat(credentials).isNotNull();
        assertThat(credentials.getClientId()).isNull();
        assertThat(credentials.getSecret()).isNull();
    }

    /**
     * The counterpart of {@code RestletOAuth2RequestTest#aNonBearerSchemeFallsBackToTheChallengeResponseRawValue},
     * asserting the opposite: CHF has no parsed challenge response to fall back to, so a non-Bearer
     * scheme yields {@code null} rather than a raw credential blob. Both are correct at the
     * {@code verify()} boundary, where either outcome is an invalid token.
     */
    @Test
    public void authorizationBearerTokenIsNullForANonBearerScheme() throws Exception {
        Request httpRequest = get("/oauth2/userinfo");
        httpRequest.getHeaders().put("Authorization", "Basic dXNlcjpwYXNz");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("userinfo", emptyMap()));

        assertThat(request.getAuthorizationBearerToken()).isNull();
    }

    // --- locale ------------------------------------------------------------------------------

    @Test
    public void localeIsThePreferredAcceptLanguage() throws Exception {
        Request httpRequest = get("/oauth2/authorize");
        httpRequest.getHeaders().put("Accept-Language", "de;q=0.5, fr;q=0.9");

        ChfOAuth2Request request = chfRequest(httpRequest, endpointContext("authorize", emptyMap()));

        assertThat(request.getLocale()).isEqualTo(Locale.forLanguageTag("fr"));
    }

    @Test
    public void localeFallsBackToTheServerDefaultWhenTheHeaderIsAbsent() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize"), endpointContext("authorize", emptyMap()));

        assertThat(request.getLocale()).isEqualTo(Locale.getDefault());
    }

    // --- servlet request / response -----------------------------------------------------------

    @Test
    public void servletRequestAndResponseComeFromTheAttributesContext() throws Exception {
        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        attributesContext.getAttributes().put(HttpServletRequest.class.getName(), servletRequest);
        attributesContext.getAttributes().put(HttpServletResponse.class.getName(), servletResponse);

        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize"), endpointContext("authorize", emptyMap()));

        assertThat(request.getHttpServletRequest()).isSameAs(servletRequest);
        assertThat(request.getHttpServletResponse()).isSameAs(servletResponse);
    }

    // --- attributes ---------------------------------------------------------------------------

    @Test
    public void attributesAreWritableAndReadBack() throws Exception {
        ChfOAuth2Request request = chfRequest(get("/oauth2/authorize"), endpointContext("authorize", emptyMap()));

        request.setAttribute("acr", "2");

        assertThat(request.getAttribute("acr")).isEqualTo("2");
        assertThat(request.<String>getParameter("acr")).isEqualTo("2");
    }

    // --- helpers ------------------------------------------------------------------------------

    private ChfOAuth2Request chfRequest(Request request, Context context) {
        return new ChfOAuth2Request(context, request);
    }

    private Request get(String path) throws Exception {
        return new Request().setMethod("GET").setUri(DEPLOYMENT_URI + path);
    }

    private Request post(String path, String contentType, String body) throws Exception {
        Request request = new Request().setMethod("POST").setUri(DEPLOYMENT_URI + path);
        request.getHeaders().put("Content-Type", contentType);
        request.getEntity().setString(body);
        return request;
    }

    /**
     * Mirrors the CHF routing of {@literal /oauth2/<endpoint>}: the {@literal oauth2} prefix is matched
     * above the realm router, the endpoint below it.
     */
    private Context endpointContext(String endpoint, java.util.Map<String, String> templateVariables) throws Exception {
        Context oauth2 = new UriRouterContext(attributesContext, "oauth2", endpoint, emptyMap());
        Context realm = new RealmContext(oauth2, Realm.root());
        return new UriRouterContext(realm, endpoint, "", templateVariables);
    }

    /**
     * Mirrors the CHF routing of {@literal /oauth2/realms/root/<endpoint>}, where the realm router matches
     * {@literal realms/root} and creates a second {@code RealmContext} before the endpoint is matched.
     */
    private Context realmPrefixedEndpointContext(String endpoint) throws Exception {
        Context oauth2 = new UriRouterContext(attributesContext, "oauth2", "realms/root/" + endpoint, emptyMap());
        Context outerRealm = new RealmContext(oauth2, Realm.root());
        Context realmRoute = new UriRouterContext(outerRealm, "realms/root", endpoint, singletonMap("realmId", "root"));
        Context innerRealm = new RealmContext(realmRoute, Realm.root());
        Context defaultRoute = new UriRouterContext(innerRealm, "", endpoint, emptyMap());
        return new UriRouterContext(defaultRoute, endpoint, "", emptyMap());
    }
}
