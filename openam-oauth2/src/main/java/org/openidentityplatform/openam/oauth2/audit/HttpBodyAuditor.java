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
package org.openidentityplatform.openam.oauth2.audit;

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.io.IOException;
import java.util.Map;

import org.forgerock.audit.AuditException;
import org.forgerock.http.protocol.Entity;
import org.forgerock.http.protocol.Form;
import org.forgerock.json.JsonValue;
import org.forgerock.util.Function;

/**
 * CHF replacement for {@code RestletBodyAuditor}: extracts selected fields from a request or response body
 * into a {@link JsonValue}. Only the listed fields are captured, only when non-null, in {@code fields} order.
 */
public abstract class HttpBodyAuditor implements Function<Entity, JsonValue, AuditException> {

    /**
     * Auditor for JSON bodies. Collapses Restlet's {@code jsonAuditor}/{@code jacksonAuditor} pair: CHF exposes
     * one {@link Entity#getJson()} (a {@link Map} for a JSON object) for request and response alike.
     */
    public static HttpBodyAuditor jsonAuditor(final String... fields) {
        return new HttpBodyAuditor() {
            @Override
            public JsonValue apply(Entity entity) throws AuditException {
                // getJson() on an empty entity throws IOException, so guard first.
                if (entity.isDecodedContentEmpty()) {
                    return json(object());
                }
                try {
                    Object body = entity.getJson();
                    if (!(body instanceof Map)) {
                        return json(object());
                    }
                    return select(fields, ((Map<?, ?>) body)::get);
                } catch (IOException e) {
                    throw new AuditException("Could not parse body as JSON - wrong body auditor?", e);
                }
            }
        };
    }

    /**
     * Auditor for {@code application/x-www-form-urlencoded} bodies. Parses via {@code fromFormString} (not
     * {@code fromRequestEntity}, which exact-matches the whole Content-Type header and empties a charset-suffixed
     * body); each auditor is only ever wired to a form endpoint, so unconditional form parsing is safe.
     */
    public static HttpBodyAuditor formAuditor(final String... fields) {
        return new HttpBodyAuditor() {
            @Override
            public JsonValue apply(Entity entity) throws AuditException {
                try {
                    Form form = new Form().fromFormString(entity.getString());
                    return select(fields, form::getFirst);
                } catch (IOException e) {
                    throw new AuditException("Could not read body - wrong body auditor?", e);
                }
            }
        };
    }

    /**
     * The auditor for when no body auditing is required.
     * @return {@code null}, matching {@code RestletBodyAuditor.noBodyAuditor()}.
     */
    public static HttpBodyAuditor noBodyAuditor() {
        return null;
    }

    /** Collects the listed fields whose looked-up value is non-null, in {@code fields} order. */
    private static JsonValue select(String[] fields, java.util.function.Function<String, Object> valueOf) {
        JsonValue result = json(object());
        for (String field : fields) {
            Object value = valueOf.apply(field);
            if (value != null) {
                result.put(field, value);
            }
        }
        return result;
    }
}
