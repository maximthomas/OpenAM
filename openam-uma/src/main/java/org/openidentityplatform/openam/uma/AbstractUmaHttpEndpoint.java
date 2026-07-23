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

import org.forgerock.http.protocol.Response;
import org.forgerock.openam.http.annotations.ExceptionHandler;

/**
 * Base for the CHF UMA protocol endpoints, carrying the one {@link ExceptionHandler} they all share so any
 * exception a handler method throws becomes the UMA error body.
 *
 * <p>The framework discovers {@code @ExceptionHandler} on inherited methods, so declaring it once here
 * covers every subclass. ⚠ Subclasses must <strong>not</strong> override {@link #onError} -- Java does not
 * carry an annotation onto an override, so an overriding method would silently lose the mapper.
 */
public abstract class AbstractUmaHttpEndpoint {

    /**
     * @param t The exception the endpoint method threw (handed over directly by the framework, not wrapped).
     * @return The UMA-shaped error response.
     */
    @ExceptionHandler
    public Response onError(Throwable t) {
        return UmaErrorResponseFactory.from(t);
    }
}
