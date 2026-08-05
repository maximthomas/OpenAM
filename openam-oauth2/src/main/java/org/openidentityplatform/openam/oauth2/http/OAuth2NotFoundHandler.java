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

import static org.forgerock.util.promise.Promises.newResultPromise;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

/**
 * Gives an unrouted {@code /oauth2} path a body (5d-1 D5).
 * <p>
 * Commons {@code Router.handle} answers a no-match with {@code newNotFound()} -- a 404 carrying <strong>no
 * entity</strong> -- and {@link OAuth2ErrorFilter} cannot rewrite what has no body. Mounted as the default route
 * of the endpoint router <em>and</em> of the nested {@code resource_set} one (a nested {@code Router} answers its
 * own 404 rather than falling through to the parent's default), this makes every routing 404 on the surface speak
 * the same vocabulary as the endpoints' own.
 * <p>
 * The OAuth2 shape is written directly rather than a CREST body for the filter to rewrite: the filter returns any
 * body already carrying {@code error} unchanged, so the two compose idempotently and this response does not depend
 * on the filter being mounted.
 */
public class OAuth2NotFoundHandler implements Handler {

    @Override
    public Promise<Response, NeverThrowsException> handle(Context context, Request request) {
        Response response = new Response(Status.NOT_FOUND);
        response.setEntity(OAuth2Error.of(Status.NOT_FOUND.getCode(), "not_found",
                Status.NOT_FOUND.getReasonPhrase()).asMap());
        return newResultPromise(response);
    }
}
