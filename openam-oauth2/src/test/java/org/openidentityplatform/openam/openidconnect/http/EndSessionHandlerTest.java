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
package org.openidentityplatform.openam.openidconnect.http;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openidconnect.OpenIDConnectEndSession;
import org.forgerock.services.context.RootContext;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.openidentityplatform.openam.oauth2.http.FreemarkerTemplateRenderer;
import org.openidentityplatform.openam.oauth2.http.OAuth2ErrorResponseFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit coverage for the CHF {@code /oauth2/connect/endSession} port.
 *
 * <p>Every error row asserts {@code application/json} as well as the body, because
 * <a href="../../../../../../../../docs/migration/restlet/phase-5b-2.md">R-5b2.1</a> is that putting this
 * endpoint on the browser base would turn each of them into an HTML page -- a total contract break that a test
 * written against the wrong base would simply assert the page for. The live shapes are pinned by 5-E3 rows
 * 8-10; these rows pin the same bytes in process.
 */
public class EndSessionHandlerTest {

    private static final String REDIRECT_URI = "http://app.invalid/logout";
    private static final String CLIENT_ID = "myclient";

    private OAuth2RequestFactory requestFactory;
    private OpenIDConnectEndSession openIDConnectEndSession;
    private ClientRegistrationStore clientRegistrationStore;
    private ClientRegistration client;
    private OAuth2Request o2;
    private EndSessionHandler handler;

    @BeforeMethod
    public void setUp() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        openIDConnectEndSession = mock(OpenIDConnectEndSession.class);
        clientRegistrationStore = mock(ClientRegistrationStore.class);
        client = mock(ClientRegistration.class);
        o2 = mock(OAuth2Request.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);
        when(clientRegistrationStore.get(eq(CLIENT_ID), any())).thenReturn(client);
        when(client.getPostLogoutRedirectUris())
                .thenReturn(Collections.singleton(URI.create(REDIRECT_URI)));

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new EndSessionHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "openIDConnectEndSession", openIDConnectEndSession);
        inject(handler, "clientRegistrationStore", clientRegistrationStore);
    }

    // --- the two no-redirect outcomes ------------------------------------------------------------

    /**
     * The absent-hint case, and the row that proves the JSON base is the right one (D1): live Restlet answers
     * this exact JSON today (an already-green e2e row predating 5-E3), and the browser base would answer a page.
     */
    @Test
    public void aMissingIdTokenHintIs400BadRequestJson() throws Exception {
        doThrow(new BadRequestException("The endSession endpoint requires an id_token_hint parameter"))
                .when(openIDConnectEndSession).endSession(o2, null);

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(bodyOf(response))
                .containsEntry("error", "bad_request")
                .containsEntry("error_description",
                        "The endSession endpoint requires an id_token_hint parameter");
    }

    /** No {@code post_logout_redirect_uri}: 204 with no entity, matching the recorded e2e row. */
    @Test
    public void noRedirectUriIs204WithNoEntity() throws Exception {
        stubParams(jwt(CLIENT_ID), null, null);

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(204);
        assertThat(response.getEntity().isDecodedContentEmpty()).isTrue();
        verify(openIDConnectEndSession).endSession(o2, jwt(CLIENT_ID));
    }

    /**
     * {@code EndSession:98-100} logs a {@code ServerException} from the session teardown and carries on --
     * "possibly already timed out". Only that one type; a {@code BadRequestException} still propagates.
     */
    @Test
    public void aServerExceptionFromTheSessionTeardownIsSwallowed() throws Exception {
        stubParams(jwt(CLIENT_ID), null, null);
        doThrow(new ServerException("already gone")).when(openIDConnectEndSession).endSession(any(), any());

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(204);
    }

    // --- the redirect ----------------------------------------------------------------------------

    /** 5-E3 row 8: no state, so the target goes out byte-for-byte -- no trailing {@code ?}. */
    @Test
    public void aRegisteredRedirectUriWithNoStateIs302Verbatim() throws Exception {
        stubParams(jwt(CLIENT_ID), REDIRECT_URI, null);

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(REDIRECT_URI);
    }

    /**
     * 5-E3 row 8: {@code state} goes in the QUERY, percent-encoded -- {@code %20} for a space, never
     * {@code +}, which is the encoding most likely to drift and which no status assertion would catch.
     *
     * <p>⚠ The slash is a <strong>recorded divergence</strong>, not parity. Live Restlet emitted
     * {@code st%20ate%2F1}; CHF emits {@code st%20ate/1}, because {@code Form.toQueryString} does not encode
     * {@code /} inside a value. Both are legal and parse identically (RFC 3986 §3.4 puts {@code /} in the
     * {@code query} production), and {@code RedirectUris} is shared with {@code /authorize}, so D8's own
     * instruction applies: record it rather than bend the encoder. Pinned on both legs by
     * {@code RestletErrorParityTest#aSlashInsideAValueIsEncodedByRestletAndNotByChf}.
     */
    @Test
    public void stateIsAppendedToTheQueryPercentEncoded() throws Exception {
        stubParams(jwt(CLIENT_ID), REDIRECT_URI, "st ate/1");

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(REDIRECT_URI + "?state=st%20ate/1");
    }

    /**
     * 5-E3 row 8, the case that settled D8's open question: {@code Reference} does <strong>no</strong>
     * normalisation, so an existing query survives verbatim and {@code state} appends with {@code &}.
     */
    @Test
    public void anExistingQueryIsPreservedAndStateAppendsWithAmpersand() throws Exception {
        String withQuery = REDIRECT_URI + "?ui=1";
        when(client.getPostLogoutRedirectUris()).thenReturn(Collections.singleton(URI.create(withQuery)));
        stubParams(jwt(CLIENT_ID), withQuery, "s2");

        Response response = dispatch();

        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(withQuery + "&state=s2");
    }

    // --- redirect validation ---------------------------------------------------------------------

    @Test
    public void aRelativeRedirectUriIs400Json() throws Exception {
        stubParams(jwt(CLIENT_ID), "/relative/cb", null);

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(bodyOf(response)).containsEntry("error", "relative_redirect_uri");
        assertThat(response.getHeaders().getFirst("Location")).isNull();
    }

    /**
     * The check is against {@code getPostLogoutRedirectUris()} ({@code EndSession:151}) -- <em>not</em> the
     * ordinary {@code redirect_uri} set. Pinned here and by the 5-E3 row 9 case that feeds it a URI registered
     * as an ordinary callback: wiring this to {@code getRedirectUris()} would still reject a stranger's URI and
     * pass every other row, while permitting logout redirects to every registered callback.
     */
    @Test
    public void anUnregisteredRedirectUriIsRedirectUriMismatch() throws Exception {
        stubParams(jwt(CLIENT_ID), "http://evil.invalid/x", null);

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(bodyOf(response)).containsEntry("error", "redirect_uri_mismatch");
        verify(client).getPostLogoutRedirectUris();
    }

    // --- D7: the client-reachable unchecked throws -----------------------------------------------

    /**
     * D7. {@code JwtReconstruction.reconstructJwt} is unchecked, so without the wrap this escapes as a
     * {@code RuntimeException}, misses the base's {@code OAuth2Exception} mapper and becomes the framework's
     * CREST <strong>500</strong>. Live Restlet answers 400 {@code server_error} (5-E3 row 10), and the input is
     * client-controlled -- so this is contract, not one of the bug paths decisions.md D3 leaves at 500.
     */
    @Test
    public void aMalformedIdTokenHintIs400ServerErrorNot500() throws Exception {
        stubParams("not.a-jwt", REDIRECT_URI, null);
        // ⚠ The throw happens INSIDE the collaborator, not in validateRedirect: OpenIDConnectEndSession
        // .endSession:68 reconstructs the JWT itself, so it fails before the handler's own reconstruction is
        // ever reached. Stubbing it is what makes this row real -- with a bare mock the call is a silent
        // no-op, control reaches validateRedirect's wrapped reconstruct, and the test passes against a
        // handler that would 500 in production.
        doThrow(new InvalidJwtException("not 3 parts"))
                .when(openIDConnectEndSession).endSession(any(), eq("not.a-jwt"));

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(bodyOf(response)).containsEntry("error", "server_error");
    }

    /**
     * The same throw with no {@code post_logout_redirect_uri} at all -- the 204 path. 5-E3 row 10's second
     * case reaches this, and {@code validateRedirect} never runs here, so only a wrap around the
     * {@code endSession} call itself can produce the recorded 400.
     */
    @Test
    public void aMalformedIdTokenHintIs400EvenWithNoRedirectUri() throws Exception {
        stubParams("not.a-jwt", null, null);
        doThrow(new InvalidJwtException("not 3 parts"))
                .when(openIDConnectEndSession).endSession(any(), eq("not.a-jwt"));

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "server_error");
    }

    /**
     * The second unchecked throw on the same path, and one D7's table does not list: {@code URI.create} raises
     * {@code IllegalArgumentException} on a target it cannot parse. 5-E3 row 10 recorded the same 400
     * {@code server_error} for it, so the wrap has to cover both parses, not just the JWT.
     */
    @Test
    public void anUnparseableRedirectUriIs400ServerErrorNot500() throws Exception {
        stubParams(jwt(CLIENT_ID), "ht tp://%%%", null);

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "server_error");
    }

    /**
     * ⚠ Security debt, reproduced deliberately: the client is selected from the {@code azp} claim of an
     * id_token whose signature is <strong>never verified</strong> ({@code EndSession:142-144}). Anyone can mint
     * a hint naming any client. This row exists so that deleting the behaviour is a deliberate act with a
     * failing test attached, rather than a silent change during a later refactor. See the
     * parity-preserved security-debt list in phase-5-oauth2.md.
     */
    @Test
    public void theAzpClaimSelectsTheClientAndNoSignatureIsVerified() throws Exception {
        // A JWT with a garbage signature, naming the client only through azp.
        stubParams(jwt(CLIENT_ID), REDIRECT_URI, null);

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        verify(clientRegistrationStore).get(eq(CLIENT_ID), any());
    }

    // --- helpers ---------------------------------------------------------------------------------

    /** A syntactically valid JWT whose {@code azp} names a client. The signature is not verified. */
    private static String jwt(String azp) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String header = b64.encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(UTF_8));
        String claims = b64.encodeToString(("{\"azp\":\"" + azp + "\"}").getBytes(UTF_8));
        return header + "." + claims + ".c2ln";
    }

    private void stubParams(String idTokenHint, String redirectUri, String state) {
        when(o2.<String>getParameter("id_token_hint")).thenReturn(idTokenHint);
        when(o2.<String>getParameter("post_logout_redirect_uri")).thenReturn(redirectUri);
        when(o2.<String>getParameter("state")).thenReturn(state);
    }

    private Response dispatch() throws Exception {
        Request request = new Request().setMethod("GET");
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
