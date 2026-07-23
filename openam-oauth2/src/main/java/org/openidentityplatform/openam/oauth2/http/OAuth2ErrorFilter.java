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

import java.io.IOException;
import java.util.Map;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

/**
 * Gives the whole {@code /oauth2} application one error shape.
 * <p>
 * Today it has two. Errors an endpoint <em>catches</em> come out RFC 6749-shaped --
 * {@code {error, error_description, ...}} -- while errors it does not are rendered by
 * {@code JSONRestStatusService} in the CREST shape, {@code {code, reason, message, ...}}. Both appear on the
 * same endpoints, and which one a client sees depends on whether the failure was anticipated. That is not a
 * contract anybody designed; this filter collapses it to the OAuth2 shape, which is the one clients parse.
 * <p>
 * It <strong>rewrites responses and never fails a request</strong>: there is nothing to catch, because the
 * framework turns a handler's throw into a response before any filter sees it.
 *
 * <h2>Scope</h2>
 * The whole {@code /oauth2} application -- the same surface {@code JSONRestStatusService} covers today.
 * <strong>Not</strong> for the {@code /json} endpoints, where the CREST shape <em>is</em> the contract.
 */
public class OAuth2ErrorFilter implements Filter {

    private static final String JSON_TYPE = "application/json";

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        return next.handle(context, request).then(this::rewriteIfCrestError);
    }

    private Response rewriteIfCrestError(Response response) {
        if (response.getStatus().getCode() < 400) {
            return response;
        }
        // Guard on the declared type before parsing. The Phase 2 filter this is modelled on relies on
        // getJson() throwing for a non-JSON body, which works but only by accident -- and here the accident
        // would be the only thing standing between this filter and Phase 5b's HTML error page.
        if (!JSON_TYPE.equalsIgnoreCase(ContentTypeHeader.valueOf(response).getType())) {
            return response;
        }
        Object entity;
        try {
            entity = response.getEntity().getJson();
        } catch (IOException e) {
            return response;
        }
        if (!(entity instanceof Map)) {
            return response;
        }
        Map<?, ?> body = (Map<?, ?>) entity;
        // Check for `error` first: an already-OAuth2-shaped body never has `code`, and a CREST body never
        // has `error`, but testing idempotency first means the filter cannot corrupt its own output.
        if (body.containsKey("error") || !body.containsKey("code")) {
            return response;
        }
        // Taken verbatim. openam-http emits the message as the exception wrote it
        // (AnnotatedMethod.crestBody), so there is no HTML escaping here to reverse -- and reversing one
        // would corrupt any CREST body that was never escaped, which this filter cannot distinguish.
        Object message = body.get("message");
        response.setEntity(OAuth2Error.of(response.getStatus().getCode(), errorFor(response),
                message == null ? null : message.toString()).asMap());
        return response;
    }

    /**
     * Derived from the wire status rather than the body's {@code code}. The status is the field the client
     * acted on, and keying off it keeps the filter correct for any {@code >= 400} CREST body whose
     * {@code code} might not match its status line. (The framework's unmapped-verb fallback historically
     * carried a {@code NotSupportedException} whose {@code code} was 501 against a 405 status; {@code Endpoints}
     * has since been fixed to emit a 405-coded body there, but deriving from the status remains the robust
     * choice.)
     * <p>
     * The whole point of this filter is to hand the client the field it dispatches on, so the statuses RFC
     * 6749 and RFC 6750 give a specific code to must get that code rather than the catch-all. A client told
     * {@code invalid_request} for a 401 corrects its parameters and retries -- forever -- where
     * {@code invalid_client} tells it to re-authenticate, which is the action that ends the loop.
     * {@code invalid_client} rather than RFC 6750's {@code invalid_token} because a 401 whose body this
     * filter had to rewrite came from the framework or an authentication filter, not from a protected
     * resource that would have produced its own bearer-token error.
     */
    private static String errorFor(Response response) {
        switch (response.getStatus().getCode()) {
        case 401:
            return "invalid_client";            // RFC 6749 5.2: client authentication failed
        case 403:
            return "access_denied";             // RFC 6749 4.1.2.1
        case 503:
            return "temporarily_unavailable";   // RFC 6749 4.1.2.1: retry later, not "the provider broke"
        default:
            // 400, 404, 405 and the rest of 4xx: the request is what was wrong, and nothing narrower is
            // knowable from a status alone.
            return response.getStatus().getCode() >= 500 ? "server_error" : "invalid_request";
        }
    }
}
