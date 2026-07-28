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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.CsrfProtection;
import org.forgerock.oauth2.core.DeviceCode;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.ResourceOwner;
import org.forgerock.oauth2.core.ResourceOwnerSessionValidator;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.core.UserInfoClaims;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerAuthenticationRequired;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.mockito.ArgumentMatchers;
import org.openidentityplatform.openam.oauth2.core.ChfOAuth2Request;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link DeviceCodeVerificationHandler}, the CHF port of
 * {@code DeviceCodeVerificationResource}.
 *
 * <h2>The two template paths are literal, and that is the point</h2>
 * The device form and thanks pages are the only OAuth2 pages Restlet rendered <em>outside</em> the
 * {@code ?display=} folder scheme ({@code :223-224} asks the template factory for the path verbatim, while the
 * consent page goes through the display-scoped representation). The rows below assert the literal paths rather
 * than reusing the handler's own constants, so a constant edited to {@code page/...} fails them.
 */
public class DeviceCodeVerificationHandlerTest {

    private static final String FORM = "templates/CodeVerificationForm.ftl";
    private static final String THANKS_PAGE = "templates/CodeThanks.ftl";
    private static final String BASE_URL = "https://openam.example.com:8443/openam";
    private static final String USER_CODE = "BDWD-HQPK";
    private static final String LOGIN_URI = "https://openam.example.com:8443/openam/UI/Login?goto=device";

    private OAuth2Request o2;
    private TokenStore tokenStore;
    private OAuth2ProviderSettings providerSettings;
    private ClientRegistration clientRegistration;
    private ResourceOwner resourceOwner;
    private ResourceOwnerSessionValidator resourceOwnerSessionValidator;
    private AuthorizationService authorizationService;
    private CsrfProtection csrfProtection;
    private ConsentPageRenderer consentPageRenderer;
    private DeviceCodeVerificationHandler handler;

    @BeforeMethod
    public void setUp() throws Exception {
        o2 = mock(OAuth2Request.class);
        when(o2.<String>getParameter("realm")).thenReturn("/");
        when(o2.getAcceptedLanguages()).thenReturn(List.of("en"));
        OAuth2RequestFactory requestFactory = mock(OAuth2RequestFactory.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);

        tokenStore = mock(TokenStore.class);
        authorizationService = mock(AuthorizationService.class);
        providerSettings = mock(OAuth2ProviderSettings.class);
        OAuth2ProviderSettingsFactory providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        when(providerSettingsFactory.get(o2)).thenReturn(providerSettings);
        clientRegistration = mock(ClientRegistration.class);
        when(clientRegistration.getClientId()).thenReturn("test_client_app");
        ClientRegistrationStore clientRegistrationStore = mock(ClientRegistrationStore.class);
        when(clientRegistrationStore.get(any(), same(o2))).thenReturn(clientRegistration);
        resourceOwner = mock(ResourceOwner.class);
        when(resourceOwner.getId()).thenReturn("demo");
        resourceOwnerSessionValidator = mock(ResourceOwnerSessionValidator.class);
        when(resourceOwnerSessionValidator.validate(o2)).thenReturn(resourceOwner);
        csrfProtection = mock(CsrfProtection.class);
        consentPageRenderer = mock(ConsentPageRenderer.class);

        handler = new DeviceCodeVerificationHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory());
        inject(handler, "templateRenderer", new FreemarkerTemplateRenderer());
        inject(handler, "baseURLProviderFactory", baseURLProviderFactory());
        inject(handler, "tokenStore", tokenStore);
        inject(handler, "authorizationService", authorizationService);
        inject(handler, "providerSettingsFactory", providerSettingsFactory);
        inject(handler, "clientRegistrationStore", clientRegistrationStore);
        inject(handler, "resourceOwnerSessionValidator", resourceOwnerSessionValidator);
        inject(handler, "csrfProtection", csrfProtection);
        inject(handler, "consentPageRenderer", consentPageRenderer);
    }

    // --- D3: seeding the device code onto the request ---------------------------------------------

    /**
     * D3 / finding 3: the whole device-code record lands on the request attributes, with exactly two
     * transformations -- {@code clientID} is renamed to {@code client_id}, and {@code scope} is joined with a
     * space. Everything else goes in verbatim, its single-element list unwrapped.
     *
     * <p>Asserted through {@link ChfOAuth2Request#getParameter} rather than through the attribute map, because
     * that is the property the rest of the flow depends on: attributes are the first source {@code getParameter}
     * consults, so seeding them is what makes every downstream collaborator resolve against the device code
     * instead of the wire.
     */
    @Test
    public void seedsDeviceCodeAttributes() throws Exception {
        ChfOAuth2Request request = deviceUserRequest();

        handler.seedAttributesFromDeviceCode(deviceCode(), request);

        assertThat(request.<String>getParameter("client_id")).isEqualTo("test_client_app");
        assertThat(request.getAttribute("clientID")).isNull();
        assertThat(request.<String>getParameter("scope")).isEqualTo("openid profile");
        assertThat(request.<String>getParameter("state")).isEqualTo("af0ifjsldkj");
        assertThat(request.<String>getParameter("nonce")).isEqualTo("n-0S6_WzA2Mj");
        assertThat(request.<String>getParameter("response_type")).isEqualTo("code");
        assertThat(request.<String>getParameter("ui_locales")).isEqualTo("fr");
        assertThat(request.<String>getParameter("user_code")).isEqualTo("BDWD-HQPK");
    }

    /**
     * ⚠ The realm write is load-bearing and surprising (R-5b2.6): a code created in {@code /alpha} and verified
     * through the root-realm URL resolves its client in {@code /alpha}. Restlet does this; reproduce it.
     */
    @Test
    public void theDeviceCodesRealmOverridesTheUrlsRealm() throws Exception {
        ChfOAuth2Request request = deviceUserRequest();
        request.setAttribute("realm", "/");

        handler.seedAttributesFromDeviceCode(deviceCode(), request);

        assertThat(request.<String>getParameter("realm")).isEqualTo("/alpha");
    }

    // --- D4: the two pages ------------------------------------------------------------------------

    /**
     * The model key-for-key against the fixture derived from
     * {@code DeviceCodeVerificationResource.getTemplateRepresentation:223-235} -- the same one the golden
     * renders were produced from, so the handler and the goldens are held to one model rather than two.
     */
    @Test
    public void theFormModelMatchesTheProducerDerivedFixture() throws Exception {
        assertThat(handler.pageModel(o2, "not_found")).isEqualTo(RendererFixtures.codeVerificationForm());
    }

    /**
     * D4: Restlet put a {@code null} {@code errorCode} into a {@code Map<String, String>}, which FreeMarker
     * reads as missing. CHF must omit the key instead -- putting an explicit null would make
     * {@code <#if errorCode??>} behave the same today but is a different model, and the fixture comparison
     * above cannot see it because the success fixture carries the null.
     */
    @Test
    public void anAbsentErrorCodeIsOmittedNotNullValued() throws Exception {
        assertThat(handler.pageModel(o2, null)).doesNotContainKey("errorCode");
    }

    @Test
    public void theFormRendersAt200AsUtf8Html() throws Exception {
        Response response = handler.page(FORM, o2, "not_found");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString())
                .contains("errorCode: \"not_found\"")
                .contains("main-device");
    }

    @Test
    public void theThanksPageRendersTheDoneMarkerAndNoErrorCode() throws Exception {
        Response response = handler.page(THANKS_PAGE, o2, null);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getEntity().getString()).contains("done: true").doesNotContain("errorCode");
    }

    /**
     * D4, the row that catches the plausible mistake: rendering these two through
     * {@code renderForDisplay} for consistency with the consent page would resolve
     * {@code templates/popup/CodeVerificationForm.ftl}, which does not exist.
     */
    @Test
    public void theDevicePagesResolveByLiteralPathWhateverTheDisplay() throws Exception {
        when(o2.<String>getParameter("display")).thenReturn("popup");

        assertThat(handler.page(FORM, o2, null).getEntity().getString()).contains("main-device");
    }

    /**
     * A broken or missing template is a deployment fault, not one of the bug paths
     * {@code decisions.md} D3 sends to the framework: it stays the contractual 400 {@code server_error} page,
     * as {@code AuthorizeHandler} already decided for the same seam.
     */
    @Test
    public void aMissingTemplateIsA400ServerErrorPageNotA500() throws Exception {
        Response response = handler.page("templates/NoSuchTemplate.ftl", o2, null);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getEntity().getString()).contains("server_error");
    }

    // --- finding 7: reading the code ---------------------------------------------------------------

    /**
     * Three inputs, one answer, and it is a <strong>200</strong>: the code-entry form carrying
     * {@code errorCode="not_found"}. The one place this provider reports a failure inside a success page --
     * pinned live by 5-E3 row 1, anonymously as well as authenticated.
     */
    @Test(dataProvider = "notFoundInputs")
    public void anUnusableUserCodeRendersTheFormAtNotFound(String label, DeviceCodeAnswer answer) throws Exception {
        when(o2.<String>getParameter("user_code")).thenReturn(USER_CODE);
        answer.apply(tokenStore, o2);

        Response response = post();

        // Assert the lookup really happened: an unstubbed readDeviceCode also returns null, so without this
        // every row here would pass through the "no code stored" branch whatever it meant to exercise.
        verify(tokenStore).readDeviceCode(USER_CODE, o2);
        assertThat(response.getStatus().getCode()).as(label).isEqualTo(200);
        assertThat(response.getEntity().getString()).as(label).contains("errorCode: \"not_found\"");
    }

    @DataProvider(name = "notFoundInputs")
    public Object[][] notFoundInputs() {
        return new Object[][] {
            {"unknown code", (DeviceCodeAnswer) (store, request) ->
                    when(store.readDeviceCode(USER_CODE, request)).thenThrow(new InvalidGrantException())},
            {"no code stored", (DeviceCodeAnswer) (store, request) ->
                    when(store.readDeviceCode(USER_CODE, request)).thenReturn(null)},
            {"already issued", (DeviceCodeAnswer) (store, request) ->
                    when(store.readDeviceCode(USER_CODE, request)).thenReturn(issuedDeviceCode())},
        };
    }

    /** Lambda-friendly stubbing hook for the row above; TestNG data providers cannot throw from a literal. */
    interface DeviceCodeAnswer {
        void apply(TokenStore store, OAuth2Request request) throws Exception;
    }

    // --- finding 7: the branch that needs no consent ------------------------------------------------

    /**
     * {@code clientsCanSkipConsent && isConsentImplied}: no decision is read, no consent page is rendered --
     * the code is authorized against the validated session and the thanks page is returned.
     */
    @Test
    public void aConsentImpliedClientAuthorisesTheCodeAndRendersThanks() throws Exception {
        DeviceCode code = deviceCode();
        deviceCodeFound(code);
        consentImplied();

        Response response = post();

        verify(tokenStore).updateDeviceCode(same(code), same(o2));
        assertThat(code.isAuthorized()).isTrue();
        assertThat(code.getResourceOwnerId()).isEqualTo("demo");
        assertThat(response.getEntity().getString()).contains("done: true");
        verifyZeroInteractions(authorizationService);
    }

    // --- finding 7: the branches that need consent --------------------------------------------------

    /**
     * No {@code decision} yet: the request goes to {@code authorizationService.authorize}, whose
     * {@code ResourceOwnerConsentRequired} is <em>not</em> an {@link org.forgerock.oauth2.core.exceptions.OAuth2Exception}
     * and so can never reach the base mapper -- it has to be caught here and turned into the consent page.
     */
    @Test
    public void noDecisionOnAConsentRequiringClientRendersTheConsentPage() throws Exception {
        deviceCodeFound(deviceCode());
        consentRequired();
        when(authorizationService.authorize(o2)).thenThrow(consentRequiredException());
        when(consentPageRenderer.render(any(), same(o2), any(Request.class)))
                .thenReturn(FreemarkerTemplateRenderer.toHtmlResponse(Status.OK, "<html>consent</html>"));

        Response response = post();

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getEntity().getString()).isEqualTo("<html>consent</html>");
        verify(tokenStore, never()).updateDeviceCode(any(), any());
    }

    @Test
    public void decisionAllowAuthorisesTheCode() throws Exception {
        DeviceCode code = deviceCode();
        deviceCodeFound(code);
        consentRequired();
        when(o2.<String>getParameter("decision")).thenReturn("allow");

        Response response = post();

        verify(tokenStore).updateDeviceCode(same(code), same(o2));
        assertThat(code.isAuthorized()).isTrue();
        assertThat(response.getEntity().getString()).contains("done: true");
        verifyZeroInteractions(authorizationService);
    }

    /**
     * ⚠ Anything that is not {@code allow} is a refusal, and the refusal <strong>deletes</strong> the code.
     * 5-E3 row 2 recorded both outcomes as the same 200 thanks page, so the wire cannot tell them apart -- the
     * store interaction is the only observable difference and therefore the only thing worth asserting.
     */
    @Test
    public void decisionDenyDeletesTheCodeAndAuthorisesNothing() throws Exception {
        DeviceCode code = deviceCode();
        deviceCodeFound(code);
        consentRequired();
        when(o2.<String>getParameter("decision")).thenReturn("deny");

        Response response = post();

        verify(tokenStore).deleteDeviceCode("test_client_app", "dev-code-id", o2);
        verify(tokenStore, never()).updateDeviceCode(any(), any());
        assertThat(code.isAuthorized()).isFalse();
        assertThat(response.getEntity().getString()).contains("done: true");
    }

    /**
     * 5-E3 row 3: a CSRF failure is the <strong>HTML</strong> error page at 400 with no {@code Location} --
     * Restlet built it with the four-argument {@code OAuth2RestletException} whose last parameter is
     * {@code state}, leaving the redirect null. Built rather than thrown here for the same reason
     * {@code AuthorizeHandler} builds its own: {@code bad_request} would otherwise be redirectable, and this
     * request's {@code redirect_uri} came off the wire unvalidated.
     */
    @Test
    public void aCsrfAttackIsA400HtmlErrorPageWithNoLocation() throws Exception {
        deviceCodeFound(deviceCode());
        consentRequired();
        when(o2.<String>getParameter("decision")).thenReturn("allow");
        when(csrfProtection.isCsrfAttack(o2)).thenReturn(true);

        Response response = post();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getEntity().getString()).contains("bad_request");
        verify(tokenStore, never()).updateDeviceCode(any(), any());
    }

    /** {@code saveConsent:211-221}: the scope stored is the <em>validated</em> one, never the raw parameter. */
    @Test
    public void saveConsentOnStoresTheValidatedScope() throws Exception {
        deviceCodeFound(deviceCode());
        consentRequired();
        when(o2.<String>getParameter("decision")).thenReturn("allow");
        when(o2.<String>getParameter("save_consent")).thenReturn("on");
        when(o2.<String>getParameter("scope")).thenReturn("openid profile");
        Set<String> validated = Set.of("openid");
        when(providerSettings.validateAuthorizationScope(same(clientRegistration), eq(Set.of("openid", "profile")),
                same(o2))).thenReturn(validated);

        post();

        verify(providerSettings).saveConsent(resourceOwner, "test_client_app", validated);
    }

    /**
     * 5-E3 recorded a **301** to {@code /UI/Login} for an unauthenticated verification, and Restlet produced it
     * with {@code Redirector(MODE_CLIENT_PERMANENT)}. Nothing in this handler catches
     * {@code ResourceOwnerAuthenticationRequired} -- it is an {@code OAuth2Exception}, so the browser base
     * turns it into the login redirect (D13). The row exists to catch a future {@code catch} clause that would
     * quietly swallow it.
     */
    @Test
    public void anUnauthenticatedResourceOwnerGets301ToTheLoginUri() throws Exception {
        deviceCodeFound(deviceCode());
        consentImplied();
        when(resourceOwnerSessionValidator.validate(o2))
                .thenThrow(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)));

        Response response = post();

        assertThat(response.getStatus().getCode()).isEqualTo(301);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(LOGIN_URI);
    }

    /**
     * {@code :157-162}: the CSRF check sits <em>inside</em> the non-empty-decision branch, so the consent-page
     * GET and the no-consent-required path never touch it. Moving it earlier would change which errors precede
     * it -- and would reject the very request that is on its way to being shown a consent form.
     */
    @Test
    public void theCsrfCheckOnlyRunsWhenADecisionWasSubmitted() throws Exception {
        deviceCodeFound(deviceCode());
        consentRequired();
        when(authorizationService.authorize(o2)).thenThrow(consentRequiredException());
        when(consentPageRenderer.render(any(), same(o2), any(Request.class)))
                .thenReturn(FreemarkerTemplateRenderer.toHtmlResponse(Status.OK, "<html>consent</html>"));

        post();

        verifyZeroInteractions(csrfProtection);
    }

    // --- the two verbs ------------------------------------------------------------------------------

    /** {@code userCodeForm():265-274}: no {@code user_code} means the bare form, and nothing is read. */
    @Test
    public void getWithoutAUserCodeRendersTheBareFormAndReadsNothing() throws Exception {
        Response response = get();

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getEntity().getString()).contains("main-device").doesNotContain("errorCode");
        verifyZeroInteractions(tokenStore);
    }

    /** With one, the GET is the POST: {@code userCodeForm} delegates to {@code verify(null)}. */
    @Test
    public void getWithAUserCodeTakesTheSamePathAsPost() throws Exception {
        when(o2.<String>getParameter("user_code")).thenReturn(USER_CODE);
        when(tokenStore.readDeviceCode(USER_CODE, o2)).thenReturn(null);

        assertThat(get().getEntity().getString()).contains("errorCode: \"not_found\"");
    }

    // --- fixtures ---------------------------------------------------------------------------------

    private static ChfOAuth2Request deviceUserRequest() throws Exception {
        return new ChfOAuth2Request(new RootContext(),
                new Request().setMethod("POST").setUri("/oauth2/device/user"));
    }

    private Response post() throws Exception {
        return dispatch("POST");
    }

    private Response get() throws Exception {
        return dispatch("GET");
    }

    private Response dispatch(String method) throws Exception {
        return Endpoints.from(handler)
                .handle(new RootContext(), new Request().setMethod(method).setUri("/oauth2/device/user"))
                .getOrThrowUninterruptibly();
    }

    private void deviceCodeFound(DeviceCode code) throws Exception {
        when(o2.<String>getParameter("user_code")).thenReturn(USER_CODE);
        when(tokenStore.readDeviceCode(USER_CODE, o2)).thenReturn(code);
    }

    private void consentImplied() throws Exception {
        when(providerSettings.clientsCanSkipConsent()).thenReturn(true);
        when(clientRegistration.isConsentImplied()).thenReturn(true);
    }

    /** {@code requireConsent = !clientsCanSkipConsent || !isConsentImplied} -- either half is enough. */
    private void consentRequired() throws Exception {
        when(providerSettings.clientsCanSkipConsent()).thenReturn(false);
        when(clientRegistration.isConsentImplied()).thenReturn(true);
    }

    private static ResourceOwnerConsentRequired consentRequiredException() {
        return new ResourceOwnerConsentRequired("Demo & Co", "A demo client",
                Map.of("profile", "View your profile"), Map.of(), new UserInfoClaims(Map.of(), Map.of()),
                "demo", true);
    }

    /** A code whose token has already been issued -- {@code isIssued()} is read off the record, not a setter. */
    private static DeviceCode issuedDeviceCode() throws Exception {
        DeviceCode code = deviceCode();
        code.put(OAuth2Constants.CoreTokenParams.ISSUED, List.of("true"));
        return code;
    }

    /** The shape {@code TokenStore.createDeviceCode} produces: every value a single-element list but scope. */
    private static DeviceCode deviceCode() {
        Set<String> scope = new LinkedHashSet<>(List.of("openid", "profile"));
        return new DeviceCode("dev-code-id", "BDWD-HQPK", "demo", "test_client_app", "n-0S6_WzA2Mj", "code",
                "af0ifjsldkj", "urn:mace:incommon:iap:silver", "consent", "fr", "demo@example.com", 300, "{}",
                1893456000L, scope, "/alpha", "challenge", "S256", "audit-id");
    }

    private static BaseURLProviderFactory baseURLProviderFactory() {
        BaseURLProvider provider = mock(BaseURLProvider.class);
        when(provider.getRootURL(ArgumentMatchers.<HttpServletRequest>any())).thenReturn(BASE_URL);
        BaseURLProviderFactory factory = mock(BaseURLProviderFactory.class);
        when(factory.get(anyString())).thenReturn(provider);
        return factory;
    }

    private static OAuth2ErrorResponseFactory errorResponseFactory() throws Exception {
        RealmNormaliser realmNormaliser = mock(RealmNormaliser.class);
        when(realmNormaliser.normalise(anyString())).thenAnswer(call -> call.getArgument(0));
        return new OAuth2ErrorResponseFactory(new FreemarkerTemplateRenderer(), baseURLProviderFactory(),
                realmNormaliser);
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
