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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.CsrfProtection;
import org.forgerock.oauth2.core.UserInfoClaims;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.xui.XUIState;
import org.openidentityplatform.openam.oauth2.core.ChfOAuth2Request;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link ConsentPageRenderer}, the shared consent collaborator.
 *
 * <h2>The assertion that carries this class</h2>
 * {@link #dataModelMatchesTheProducerDerivedFixture()} compares the model key-for-key <em>and
 * type-for-type</em> against {@link RendererFixtures#authorize()} -- the model derived from
 * {@code ConsentRequiredResource.getDataModel} itself, and the same one the golden files were rendered from.
 * That is the only assertion that can catch R-5b1.2: Restlet seeded nine OAuth2 parameters <em>implicitly</em>
 * from the query map, so an enumerating port that misses one turns a template's {@code <#if x??>} false and
 * silently drops a field from the consent page. A hand-written expectation would be wrong in exactly the same
 * way the port was.
 *
 * <h2>Why the query-only rows matter more than they look</h2>
 * The producer reads {@code getQuery().getValuesMap()} -- the query string, never the POST body. On
 * {@code /authorize} that is invisible, because its consent page is only reached on {@code GET}. It is not
 * invisible on the device flow: 5b-2 renders this same model from inside a {@code @Post}, where
 * {@code getParameter} would fall through to the form body and populate the model with values Restlet never
 * put there (R-5b1.9). Hence {@link #queryParametersWinOverAConflictingFormBody()}.
 */
public class ConsentPageRendererTest {

    private static final String BASE_URL = "https://openam.example.com:8443/openam";
    private static final String CSRF = "1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809";
    private static final String QUERY = "client_id=test_client_app&response_type=code";

    private RealmTestHelper realmTestHelper;
    private ConsentPageRenderer renderer;
    private XUIState xuiState;
    private CsrfProtection csrfProtection;

    @BeforeMethod
    public void setUp() throws Exception {
        realmTestHelper = new RealmTestHelper();
        realmTestHelper.setupRealmClass();

        xuiState = mock(XUIState.class);
        when(xuiState.isXUIEnabled()).thenReturn(true);
        csrfProtection = mock(CsrfProtection.class);
        when(csrfProtection.createCsrfToken(any())).thenReturn(CSRF);

        BaseURLProvider provider = mock(BaseURLProvider.class);
        when(provider.getRootURL(org.mockito.ArgumentMatchers.<HttpServletRequest>any())).thenReturn(BASE_URL);
        BaseURLProviderFactory baseURLProviderFactory = mock(BaseURLProviderFactory.class);
        when(baseURLProviderFactory.get(anyString())).thenReturn(provider);

        renderer = new ConsentPageRenderer(new FreemarkerTemplateRenderer(), xuiState, baseURLProviderFactory,
                csrfProtection);
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
    }

    /** R-5b1.2. Every key the producer emits, with the type the templates require. */
    @Test
    public void dataModelMatchesTheProducerDerivedFixture() throws Exception {
        Request request = authorizeRequest(QUERY
                + "&redirect_uri=https%3A%2F%2Frp.example.com%2Fcallback"
                + "&scope=openid+profile+email&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj"
                + "&acr=urn%3Amace%3Aincommon%3Aiap%3Asilver");
        ChfOAuth2Request o2 = chfRequest(request, "BDWD-HQPK", "en");

        Map<String, Object> model = renderer.dataModel(consentRequired(), o2, request);

        Map<String, Object> expected = RendererFixtures.authorize();
        assertThat(model.keySet()).containsExactlyInAnyOrderElementsOf(expected.keySet());
        for (Map.Entry<String, Object> entry : expected.entrySet()) {
            // target is the one key whose value is a function of this request's own URI rather than of the
            // producer's logic -- the fixture's was captured from a two-parameter request. Its type is still
            // checked here; its value has three dedicated tests below.
            if (!"target".equals(entry.getKey())) {
                assertThat(model.get(entry.getKey())).as("key " + entry.getKey()).isEqualTo(entry.getValue());
            }
            if (entry.getValue() != null) {
                assertThat(model.get(entry.getKey())).as("type of " + entry.getKey())
                        .isInstanceOf(entry.getValue().getClass());
            }
        }
    }

    /**
     * R-5b1.2 as a <em>standing</em> guard rather than a snapshot. The fixture row above proves the model
     * matches the producer's today; this proves the model still covers the <strong>templates</strong>, which
     * is the half that rots silently: {@code QUERY_KEYS} enumerates what Restlet copied in bulk, so a template
     * that later grows a {@code ${prompt}} nobody adds to the list still renders -- {@code <#if prompt??>} just
     * goes false and the field disappears from the consent page with no error anywhere.
     *
     * <p>Nothing is written down twice. The supplied set comes from a real {@link ConsentPageRenderer#dataModel}
     * call, so phase 1 and phase 3 subtract themselves and only the query -- the thing under test -- is stated,
     * as the query string a request would actually carry. That also makes the row catch a dropped phase-3 key,
     * not just a missing query name.
     */
    @Test
    public void everyTemplateVariableIsSuppliedByTheModel() throws Exception {
        Request request = authorizeRequest("client_id=c&response_type=code&redirect_uri=https%3A%2F%2Frp%2Fcb"
                + "&scope=openid&state=s&nonce=n&acr=a&ui_locales=en&realm=%2F");

        Set<String> supplied = renderer.dataModel(consentRequired(), chfRequest(request, null), request).keySet();

        for (OAuth2Constants.DisplayType display : OAuth2Constants.DisplayType.values()) {
            String template = "templates/" + display.getFolder() + "/authorize.ftl";
            assertThat(variablesRead(template)).as(template).isSubsetOf(supplied);
        }
    }

    /**
     * R-5b1.9, the row that protects 5b-2. The producer copies the <em>query</em> map; a
     * {@code getParameter}-based port would read the form body on a POST and leak it into the page.
     */
    @Test
    public void queryParametersWinOverAConflictingFormBody() throws Exception {
        Request request = new Request().setMethod("POST")
                .setUri("http://openam.example.com:8080/openam/oauth2/authorize?" + QUERY
                        + "&scope=openid&state=from-query");
        request.getHeaders().put("Content-Type", "application/x-www-form-urlencoded");
        request.setEntity("scope=EVIL&state=from-body&nonce=from-body");

        Map<String, Object> model = renderer.dataModel(consentRequired(), chfRequest(request, null), request);

        assertThat(model).containsEntry("scope", "openid").containsEntry("state", "from-query");
        assertThat(model).doesNotContainValue("EVIL").doesNotContainValue("from-body");
        // nonce is only in the body, so the producer never saw it: omitted, not null-valued.
        assertThat(model).doesNotContainKey("nonce");
    }

    /**
     * The producer's phase 2 (`putAll` of the query map) overlays phase 1 (the request attributes), so a
     * raw {@code ?realm=} beats the router-resolved value. {@code getParameter} has the opposite precedence.
     */
    @Test
    public void aRawRealmQueryParameterOverlaysTheResolvedRealmAttribute() throws Exception {
        Request request = authorizeRequest(QUERY + "&realm=alpha");

        Map<String, Object> model = renderer.dataModel(consentRequired(), chfRequest(request, null), request);

        assertThat(model).containsEntry("realm", "alpha");
    }

    /** Phase 1 supplies it when the query does not. */
    @Test
    public void theResolvedRealmIsUsedWhenTheQueryCarriesNone() throws Exception {
        Request request = authorizeRequest(QUERY);

        Map<String, Object> model = renderer.dataModel(consentRequired(), chfRequest(request, null), request);

        assertThat(model).containsEntry("realm", "/");
    }

    /**
     * CVE-2026-62280: {@code display_scope} is written in phase 3, after the query copy, precisely so a
     * client cannot supply its own. Reversing the phases reintroduces the injection.
     */
    @Test
    public void displayScopeCannotBeSuppliedByTheClient() throws Exception {
        Request request = authorizeRequest(QUERY + "&display_scope=INJECTED");

        Map<String, Object> model = renderer.dataModel(consentRequired(), chfRequest(request, null), request);

        assertThat(model.get("display_scope")).isEqualTo(List.of("View your profile", "View your email address"));
    }

    /** A Restlet {@code getValuesMap()} never contains an absent parameter, so the templates' `??` hold. */
    @Test
    public void absentOptionalParametersAreOmittedNotNullValued() throws Exception {
        Request request = authorizeRequest(QUERY);

        Map<String, Object> model = renderer.dataModel(consentRequired(), chfRequest(request, null), request);

        assertThat(model).doesNotContainKey("nonce").doesNotContainKey("acr").doesNotContainKey("ui_locales");
    }

    /**
     * R-5b1.8: {@code target} comes from the CHF request URI, so it carries the context path and the query --
     * and, unlike a servlet-request reconstruction, it follows a query mutation. The consent form posts back
     * to this value.
     */
    @Test
    public void targetIsTheChfUriIncludingContextPathAndQuery() throws Exception {
        Request request = authorizeRequest(QUERY);

        Map<String, Object> model = renderer.dataModel(consentRequired(), chfRequest(request, null), request);

        assertThat(model).containsEntry("target", "/openam/oauth2/authorize?" + QUERY);
    }

    @Test
    public void targetFollowsAQueryMutation() throws Exception {
        Request request = authorizeRequest(QUERY);
        ChfOAuth2Request o2 = chfRequest(request, null);
        o2.setQueryParameter("max_age", "60");

        Map<String, Object> model = renderer.dataModel(consentRequired(), o2, request);

        assertThat((String) model.get("target")).contains("max_age=60");
    }

    /**
     * ⚠ {@code target} must carry the <strong>raw, percent-encoded</strong> query, which is what Restlet's
     * {@code Reference.getQuery()} returns (its decoding form is the {@code getQuery(boolean)} overload) and
     * what 5-E2 row 9 recorded off a live consent page before posting back to it successfully.
     * {@code MutableUri.getQuery()} is the <em>decoded</em> accessor -- {@code getRawQuery()} is the raw one --
     * so the obvious call silently rewrites {@code redirect_uri=https%3A%2F%2Frp%2Fcb%3Fa%3D1} into a URL whose
     * {@code &} and {@code =} the consent POST then re-parses as extra top-level parameters, and the post-back
     * fails with a redirect-URI mismatch. None of the other target rows can see this: their queries are
     * byte-identical encoded and decoded.
     */
    @Test
    public void targetKeepsThePercentEncodingOfTheQuery() throws Exception {
        String encoded = "client_id=c&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb%3Fa%3D1%26b%3D2"
                + "&scope=openid+profile&state=a%20b";
        Request request = new Request().setMethod("GET")
                .setUri("http://openam.example.com:8080/openam/oauth2/authorize?" + encoded);

        Map<String, Object> model = renderer.dataModel(consentRequired(), chfRequest(request, null), request);

        assertThat(model).containsEntry("target", "/openam/oauth2/authorize?" + encoded);
    }

    /** No query at all: the producer appends no "?" (StringUtils.isBlank guard). */
    @Test
    public void targetHasNoQuestionMarkWhenTheQueryIsEmpty() throws Exception {
        Request request = new Request().setMethod("GET")
                .setUri("http://openam.example.com:8080/openam/oauth2/authorize");

        Map<String, Object> model = renderer.dataModel(consentRequired(), chfRequest(request, null), request);

        assertThat(model).containsEntry("target", "/openam/oauth2/authorize");
    }

    /** The accepted-language tags, space-joined -- including the "*" an absent header yields. */
    @Test
    public void localeIsTheSpaceJoinedAcceptedLanguages() throws Exception {
        Request request = authorizeRequest(QUERY);
        ChfOAuth2Request o2 = chfRequest(request, null, "en-GB", "fr");

        Map<String, Object> model = renderer.dataModel(consentRequired(), o2, request);

        assertThat(model).containsEntry("locale", "en-GB fr");
    }

    @Test
    public void localeIsTheWildcardWhenNoAcceptLanguageWasSent() throws Exception {
        Request request = authorizeRequest(QUERY);

        Map<String, Object> model = renderer.dataModel(consentRequired(), chfRequest(request, null), request);

        assertThat(model).containsEntry("locale", "*");
    }

    // --- rendering -------------------------------------------------------------------------------

    @Test
    public void rendersThePageAt200AsUtf8Html() throws Exception {
        Request request = authorizeRequest(QUERY);

        Response response = renderer.render(consentRequired(), chfRequest(request, null), request);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString()).contains("View your profile");
    }

    /** Risk #21: the templates are ASCII, so only a non-ASCII model can prove the bytes are UTF-8. */
    @Test
    public void aNonAsciiUserNameRoundTripsAsUtf8() throws Exception {
        Request request = authorizeRequest(QUERY);

        Response response = renderer.render(consentRequired(), chfRequest(request, null), request);

        byte[] wire = response.getEntity().getBytes();
        assertThat(new String(wire, StandardCharsets.UTF_8)).contains(RendererFixtures.NON_ASCII_USER_NAME);
    }

    @Test
    public void displaySelectsTheTouchTemplate() throws Exception {
        Request request = authorizeRequest(QUERY + "&display=touch");

        Response response = renderer.render(consentRequired(), chfRequest(request, null), request);

        assertThat(response.getEntity().getString()).contains("width=device-width");
    }

    /** {@code ?display=popup} renders the page and injects it into the wrapper as {@code htmlCode}. */
    @Test
    public void displayPopupComposesTheWrapper() throws Exception {
        Request request = authorizeRequest(QUERY + "&display=popup");

        Response response = renderer.render(consentRequired(), chfRequest(request, null), request);

        String html = response.getEntity().getString();
        assertThat(html).contains("function poponload()");     // the wrapper
        assertThat(html).contains("View your profile");        // the page it embedded
    }

    /**
     * {@code display} is read with {@code getParameter}, not {@code getQueryParameter}:
     * {@code OAuth2Representation:72} used {@code getParameter}, and it was never one of the keys the
     * {@code getQuery().getValuesMap()} copy supplied -- so R-5b1.9's query-only rule does not reach it. The
     * distinction only bites where this collaborator is reused from a {@code @Post}, which is exactly what
     * 5b-2's device flow does: a consent form carrying {@code display=touch} in its body must still select the
     * touch template.
     */
    @Test
    public void displayIsReadFromTheFormBodyToo() throws Exception {
        Request request = new Request().setMethod("POST")
                .setUri("http://openam.example.com:8080/openam/oauth2/authorize?" + QUERY);
        request.getHeaders().put("Content-Type", "application/x-www-form-urlencoded");
        request.setEntity("display=touch");

        Response response = renderer.render(consentRequired(), chfRequest(request, null), request);

        assertThat(response.getEntity().getString()).contains("width=device-width");
    }

    /** 3c-1 D7 preserved the IAE so 5b could map it; the renderer must let it escape to the handler (D7). */
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void anUnknownDisplayRaisesIllegalArgumentException() throws Exception {
        Request request = authorizeRequest(QUERY + "&display=bogus");

        renderer.render(consentRequired(), chfRequest(request, null), request);
    }

    // --- fixtures ---------------------------------------------------------------------------------

    /** An interpolation, or a directive up to its own {@code >}. */
    private static final Pattern EXPRESSION = Pattern.compile("\\$\\{[^}]*}|</?#[^>]*>");
    /** An identifier that is neither a {@code ?builtin} nor a {@code .property}. */
    private static final Pattern IDENTIFIER = Pattern.compile("(?<![?.\\w])[a-zA-Z_]\\w*");
    private static final Pattern LOOP_VARIABLE = Pattern.compile("<#list\\b[^>]*\\bas\\s+(\\w+)");
    private static final Set<String> KEYWORDS = Set.of("as", "in", "true", "false");

    /**
     * Every model variable a template reads: the identifiers inside its interpolations and directives, less
     * the directive names, string literals, built-ins, keywords and {@code <#list ... as x>} variables.
     * <p>
     * Deliberately an <em>over</em>-approximation on anything it does not model (a {@code <#assign>}, an
     * operator it has not been taught): an unrecognised name fails the build and someone looks, whereas an
     * under-approximation would let the very drift this guards against pass unnoticed.
     */
    private static Set<String> variablesRead(String resource) throws Exception {
        String ftl;
        try (java.io.InputStream stream =
                     ConsentPageRendererTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(stream).as(resource).isNotNull();
            ftl = new String(stream.readAllBytes(), StandardCharsets.UTF_8).replaceAll("(?s)<#--.*?-->", "");
        }

        Set<String> names = new TreeSet<>();
        Matcher expressions = EXPRESSION.matcher(ftl);
        while (expressions.find()) {
            String expression = expressions.group()
                    .replaceFirst("^(\\$\\{|</?#\\w*)", "")        // the opener, and the directive's own name
                    .replaceAll("'[^']*'|\"[^\"]*\"", "");         // string literals
            Matcher identifiers = IDENTIFIER.matcher(expression);
            while (identifiers.find()) {
                names.add(identifiers.group());
            }
        }
        names.removeAll(KEYWORDS);
        Matcher loops = LOOP_VARIABLE.matcher(ftl);
        while (loops.find()) {
            names.remove(loops.group(1));
        }
        return names;
    }

    private static Request authorizeRequest(String query) throws Exception {
        return new Request().setMethod("GET")
                .setUri("http://openam.example.com:8080/openam/oauth2/authorize?" + query);
    }

    private ChfOAuth2Request chfRequest(Request request, String userCode, String... acceptLanguages)
            throws Exception {
        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getHeaders("Accept-Language"))
                .thenReturn(java.util.Collections.enumeration(List.of(acceptLanguages)));
        AttributesContext attributes = new AttributesContext(new RootContext());
        attributes.getAttributes().put(HttpServletRequest.class.getName(), servletRequest);
        Context context = new RealmContext(attributes, realmTestHelper.mockRealm());
        if (userCode != null) {
            request.setUri(request.getUri().toString() + "&user_code=" + userCode);
        }
        return new ChfOAuth2Request(context, request);
    }

    /** The same shape {@code RendererFixtures.authorize()} was derived from. */
    private static ResourceOwnerConsentRequired consentRequired() {
        Map<String, String> scopeDescriptions = new LinkedHashMap<>();
        scopeDescriptions.put("profile", "View your profile");
        scopeDescriptions.put("email", "View your email address");

        Map<String, String> claimDescriptions = new LinkedHashMap<>();
        claimDescriptions.put("email", "Email address");
        claimDescriptions.put("name", "Full name");

        Map<String, Object> claimValues = new LinkedHashMap<>();
        claimValues.put("email", "demo@example.com");
        claimValues.put("name", "Demo User");
        Map<String, List<String>> compositeScopes = new LinkedHashMap<>();
        compositeScopes.put("email", List.of("email"));

        UserInfoClaims claims = new UserInfoClaims(claimValues, compositeScopes);
        return new ResourceOwnerConsentRequired("Demo & Co", "A demo client for the \"consent\" page",
                scopeDescriptions, claimDescriptions, claims, RendererFixtures.NON_ASCII_USER_NAME, true);
    }
}
