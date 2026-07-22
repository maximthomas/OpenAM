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
 * Copyright 2015 ForgeRock AS.
 * Portions copyright 2026 3A Systems LLC.
 */

package org.forgerock.openam.http.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Mark a method that handles exceptions thrown by a service method and turns them into a response.
 * <p>
 * The method takes the exception as its only unannotated parameter, may take {@link Contextual}
 * parameters as a service method does, and returns one of the same types. The handler whose
 * parameter type most closely matches the thrown exception is used; if none matches, the
 * framework's own error response is returned. Only the exception the annotated method itself
 * threw is dispatched here; a failure of the framework invoking it is not.
 * <p>
 * The annotation is found on inherited methods, but Java does not inherit it onto an override:
 * a subclass that overrides an annotated method must annotate it again.
 * @since 13.0.0
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface ExceptionHandler {
}
