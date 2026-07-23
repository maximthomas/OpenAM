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
package org.openidentityplatform.openam.uma;

import java.util.LinkedHashMap;
import java.util.Map;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.openam.uma.UmaException;

/**
 * Renders an exception thrown by a UMA endpoint into the spec's error body
 * (https://docs.kantarainitiative.org/uma/draft-uma-core.html#uma-error-response):
 * {@code {error, error_description, [detail...]}}.
 *
 * <p>The CHF replacement for the Restlet {@code UmaExceptionHandler}. It preserves that class's exact
 * if/else chain, but dispatches on the thrown exception <em>directly</em>: CHF's {@code @ExceptionHandler}
 * receives the real exception, whereas Restlet wrapped it, so the {@code getCause()} unwrap is gone.
 */
public final class UmaErrorResponseFactory {

    private UmaErrorResponseFactory() {
    }

    /**
     * @param t The exception the endpoint threw.
     * @return A response carrying the UMA error body and the exception's status ({@code 500} for anything
     *     that is not an {@link OAuth2Exception}).
     */
    public static Response from(Throwable t) {
        if (t instanceof UmaException) {
            UmaException e = (UmaException) t;
            return response(e.getStatusCode(), e.getError(), e.getMessage(), e.getDetail());
        } else if (t instanceof OAuth2Exception) {
            OAuth2Exception e = (OAuth2Exception) t;
            return response(e.getStatusCode(), e.getError(), e.getMessage(), null);
        }
        return response(500, "server_error", t.getMessage(), null);
    }

    private static Response response(int statusCode, String error, String description, JsonValue detail) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        if (detail != null) {
            body.putAll(detail.asMap());
        }
        // setEntity(Map) routes to setJson, so the wire type is application/json; charset=UTF-8.
        return new Response(Status.valueOf(statusCode)).setEntity(body);
    }
}
