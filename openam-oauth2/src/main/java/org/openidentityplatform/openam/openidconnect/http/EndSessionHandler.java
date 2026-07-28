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

import static org.forgerock.oauth2.core.Utils.isEmpty;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

import jakarta.inject.Inject;

import org.forgerock.http.header.LocationHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.exceptions.JwtRuntimeException;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.RelativeRedirectUriException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;
import org.forgerock.openidconnect.OpenIDConnectEndSession;
import org.openidentityplatform.openam.oauth2.http.AbstractOAuth2HttpJsonEndpoint;
import org.openidentityplatform.openam.oauth2.http.RedirectUris;
import org.forgerock.services.context.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CHF OpenID Connect end-session endpoint ({@code /oauth2/connect/endSession}), porting the Restlet
 * {@code EndSession}.
 *
 * <p>GET only, as today. Three outcomes: <strong>204</strong> with no entity when no
 * {@code post_logout_redirect_uri} was supplied, <strong>302</strong> to a registered post-logout URI
 * otherwise, and the OAuth2 JSON error body for everything else.
 *
 * <p><strong>JSON, not a page</strong> (D1). The Restlet's {@code doCatch} called the <em>2-arg</em>
 * {@code ExceptionHandler.handle}, which renders {@code exception.asMap()} as JSON; the 4-arg overload used by
 * {@code AuthorizeResource} renders {@code page/error.ftl}. That arity is the whole error contract, so this
 * extends {@link AbstractOAuth2HttpJsonEndpoint} and must not override its {@code onError}.
 *
 * <p><strong>No cache headers, no hooks, no verb or content-type validation</strong>: this endpoint was never
 * wrapped by the Restlet {@code OAuth2Filter}, so {@code withErrorHeaders} is left at the base default and an
 * unsupported verb is the framework's 405.
 *
 * <p>⚠ <strong>Security debt, reproduced deliberately.</strong> The client is resolved from the {@code azp}
 * claim of an id_token whose signature is never verified, so the post-logout URI is validated against a client
 * the caller chose. Carried over verbatim from {@code EndSession:142-144}; see the parity-preserved
 * security-debt list in phase-5-oauth2.md. Pinned by a named test so removing it is a deliberate act.
 */
public class EndSessionHandler extends AbstractOAuth2HttpJsonEndpoint {

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");

    @Inject
    private OpenIDConnectEndSession openIDConnectEndSession;
    @Inject
    private ClientRegistrationStore clientRegistrationStore;

    /**
     * @param ctx the request context.
     * @param request the CHF GET request, carrying {@code id_token_hint}, {@code post_logout_redirect_uri}
     *     and {@code state}.
     * @return 302 to the post-logout URI, or 204 when none was requested.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Get
    public Response endSession(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        String idToken = o2.getParameter(OAuth2Constants.Params.END_SESSION_ID_TOKEN_HINT);
        String redirectUri = o2.getParameter(OAuth2Constants.Params.POST_LOGOUT_REDIRECT_URI);
        String state = o2.getParameter(OAuth2Constants.Params.STATE);

        try {
            openIDConnectEndSession.endSession(o2, idToken);
        } catch (ServerException e) {
            // Reproduced verbatim (EndSession:98-100): the session may simply have timed out already, and
            // that is not a reason to fail the logout. Only ServerException -- a BadRequestException (the
            // missing-hint case) still propagates to the mapper.
            logger.warn("Error while removing session, possibly already timed out. Skipping...", e);
        } catch (JwtRuntimeException e) {
            // ⚠ D7, and NOT redundant with the wrap in validateRedirect. OpenIDConnectEndSession.endSession:68
            // reconstructs the id_token ITSELF, so a malformed hint throws here -- before validateRedirect
            // exists, and on the no-redirect_uri path where validateRedirect never runs at all. Restlet's
            // doCatch caught it and answered 400 server_error (5-E3 row 10, both cases); without this the
            // unchecked throw misses the base's OAuth2Exception mapper and becomes the framework's 500.
            // Typed to JwtRuntimeException rather than RuntimeException so a bug in destroySession still
            // surfaces as a 500 (decisions.md D3).
            throw new ServerException(e);
        }

        if (isEmpty(redirectUri)) {
            return new Response(Status.NO_CONTENT);
        }
        validateRedirect(o2, idToken, redirectUri);
        // D8. Restlet appended state with Reference.addQueryParameter and emitted the target verbatim
        // otherwise; compose(QUERY) does the same, and an empty map leaves the URI untouched -- which is
        // exactly the `state != null && !state.isEmpty()` guard the Restlet had.
        Map<String, String> params = isEmpty(state)
                ? Collections.emptyMap()
                : Collections.singletonMap(OAuth2Constants.Params.STATE, state);
        return redirectTo(RedirectUris.compose(redirectUri, params, UrlLocation.QUERY));
    }

    private void validateRedirect(OAuth2Request o2, String idToken, String redirectUri)
            throws InvalidClientException, RedirectUriMismatchException, RelativeRedirectUriException,
            NotFoundException, ServerException {

        SignedJwt jwt;
        try {
            // D7. Unchecked, and client-controlled. Restlet's doCatch turned it into a 400 server_error;
            // without the wrap it misses the base's OAuth2Exception mapper and becomes the framework's 500.
            // Typed rather than a bare RuntimeException so only the parse collapses (decisions.md D3).
            jwt = new JwtReconstruction().reconstructJwt(idToken, SignedJwt.class);
        } catch (JwtRuntimeException e) {
            throw new ServerException(e);
        }

        // ⚠ Statement order is load-bearing and matches EndSession:142-146: the client is resolved BEFORE the
        // URI is parsed. With both bad -- an azp naming an unregistered client and an unparseable target --
        // Restlet answered invalid_client, not server_error. Hoisting the parse would silently swap them.
        String clientId = (String) jwt.getClaimsSet().getClaim(OAuth2Constants.JWTTokenParams.AZP);
        ClientRegistration client = clientRegistrationStore.get(clientId, o2);

        URI requestedUri;
        try {
            requestedUri = URI.create(redirectUri);      // D7 again: unchecked IAE on an unparseable target
        } catch (IllegalArgumentException e) {
            throw new ServerException(e);
        }

        if (!requestedUri.isAbsolute()) {
            throw new RelativeRedirectUriException();
        }
        // The POST-LOGOUT set, not the ordinary redirect_uri set (EndSession:151). They are separate
        // registrations, and conflating them would permit logout redirects to every registered callback.
        if (!client.getPostLogoutRedirectUris().contains(requestedUri)) {
            throw new RedirectUriMismatchException();
        }
    }

    /** {@code Redirector(MODE_CLIENT_FOUND)} is a 302; the target is emitted verbatim. Twin of AuthorizeHandler's. */
    private static Response redirectTo(String target) {
        Response response = new Response(Status.FOUND);
        response.getHeaders().put(LocationHeader.NAME, target);
        return response;
    }
}
