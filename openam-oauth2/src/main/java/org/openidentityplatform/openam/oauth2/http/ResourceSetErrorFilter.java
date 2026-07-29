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
import org.forgerock.http.protocol.Status;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

/**
 * Gives {@code /oauth2/resource_set} the error vocabulary its own specification defines, rather than the
 * generic {@code /oauth2} one.
 * <p>
 * This is the port of Restlet's {@code ResourceSetRegistrationExceptionFilter}, and
 * {@code resource_set} is the one {@code /oauth2} route that keeps a non-generic error vocabulary --
 * the same carve-out UMA got, and for the same reason
 * (<a href="https://tools.ietf.org/html/draft-hardjono-oauth-resource-reg-04#section-3">
 * draft-hardjono-oauth-resource-reg-04 3</a>).
 *
 * <h2>Ordering</h2>
 * Mounted <strong>inside</strong> the root {@link OAuth2ErrorFilter}, and on the handler rather than the
 * router:
 * <pre>
 * OAuth2ErrorFilter( ... router ... ResourceSetErrorFilter( audit( protect( Endpoints.from(handler) ) ) ) )
 * </pre>
 * This filter runs first on the way out and always leaves an {@code error} key, so the root filter's
 * {@code containsKey("error")} guard returns the body untouched -- idempotent by construction. Without the
 * inner filter a 405 here would come out as the generic {@code method_not_allowed}, silently retargeting this
 * endpoint's spec-defined error onto {@code /oauth2}'s. Wrapping the <em>router</em> instead would turn a
 * router 404 into a 500 via the catch-all below.
 *
 * <h2>The guard</h2>
 * Restlet's filter acted only when {@code response.getEntity() == null} -- it existed to fill in a body the
 * endpoint had not produced, never to overwrite one. The CHF equivalent is "body absent <em>or</em>
 * CREST-shaped", because {@code Endpoints.from} does not leave an unmapped verb body-less the way Restlet
 * did: it emits a CREST {@code {code, reason, message}}. Anything already carrying {@code error} is returned
 * untouched.
 * <p>
 * Like the root filter, this <strong>rewrites responses and never fails a request</strong>.
 */
public class ResourceSetErrorFilter implements Filter {

    /** 5-E4 row 14: the endpoint's errors are bare {@code application/json}, with no charset parameter. */
    private static final String JSON_TYPE = "application/json";

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        return next.handle(context, request).then(this::rewrite);
    }

    private Response rewrite(Response response) {
        if (response.getStatus().getCode() < 400) {
            return response;
        }
        boolean empty = response.getEntity().isRawContentEmpty();
        Map<?, ?> crest = empty ? null : crestBody(response);
        if (!empty && crest == null) {
            return response;
        }
        switch (response.getStatus().getCode()) {
        case 405:
            return replaceBody(response, "unsupported_method_type", null);
        case 412:
            // D6's conditional path returns a bare 412 so that this filter supplies the body, keeping both
            // filters' contracts in one place rather than duplicating them inline in the handler.
            return replaceBody(response, "precondition_failed", null);
        default:
            // The honest translation of producer B's else branch. On Restlet it was reached with a null
            // throwable and crashed, so what it *did* is not a contract worth reproducing; this is the shape
            // it was written to answer. The status really does become 500, whatever came in.
            Object message = crest == null ? null : crest.get("message");
            response.setStatus(Status.INTERNAL_SERVER_ERROR);
            return replaceBody(response, "server_error", message == null ? null : message.toString());
        }
    }

    /** The body if it is CREST-shaped JSON ({@code code} present, {@code error} absent), otherwise null. */
    private static Map<?, ?> crestBody(Response response) {
        if (!JSON_TYPE.equalsIgnoreCase(ContentTypeHeader.valueOf(response).getType())) {
            return null;
        }
        Object entity;
        try {
            entity = response.getEntity().getJson();
        } catch (IOException e) {
            return null;
        }
        if (!(entity instanceof Map)) {
            return null;
        }
        Map<?, ?> body = (Map<?, ?>) entity;
        return body.containsKey("error") || !body.containsKey("code") ? null : body;
    }

    private static Response replaceBody(Response response, String error, String description) {
        response.setEntity(OAuth2Error.of(response.getStatus().getCode(), error, description).asMap());
        // setEntity(Map) -> setJson writes "application/json; charset=UTF-8"; the measured wire form carries
        // no charset, and the 5-E4 rows assert it exactly, so re-stamp the header after the body.
        response.getHeaders().put(ContentTypeHeader.NAME, JSON_TYPE);
        return response;
    }
}
