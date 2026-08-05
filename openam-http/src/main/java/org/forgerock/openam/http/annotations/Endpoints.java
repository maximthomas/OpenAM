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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2026 3A Systems LLC.
 */

package org.forgerock.openam.http.annotations;

import static org.forgerock.util.promise.Promises.*;

import com.google.inject.Key;
import com.sun.identity.shared.debug.Debug;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.services.context.Context;
import org.forgerock.util.Function;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

/**
 * Convenience class for creating {@code Handler}s from classes that contain annotated methods
 * that handle requests.
 * @since 13.0.0
 */
public final class Endpoints {

    private static final Debug DEBUG = Debug.getInstance("frRest");
    private static final String HEADER_X_HTTP_METHOD_OVERRIDE = "X-HTTP-Method-Override";
    private static final String HEADER_ALLOW = "Allow";
    /** The verbs {@link #from(Object)} maps to an annotation, in the order {@code Allow} lists them. */
    private static final String[] MAPPED_VERBS = {"DELETE", "GET", "POST", "PUT"};

    /**
     * Produce a {@code Handler} from the annotated methods on the provided object.
     * <p>
     * This method currently only distinguishes requests by their method type. In future this
     * should be extended to support selection by request and response media types, and request
     * path.
     * @param obj The object containing annotated methods.
     * @return A new {@code Handler}.
     */
    public static Handler from(final Object obj) {
        final Map<Class<? extends Throwable>, AnnotatedMethod> exceptionHandlers =
                AnnotatedMethod.findExceptionHandlers(obj);
        final Map<String, AnnotatedMethod> methods = new HashMap<>();
        methods.put("DELETE", AnnotatedMethod.findMethod(obj, Delete.class, exceptionHandlers));
        methods.put("GET", AnnotatedMethod.findMethod(obj, Get.class, exceptionHandlers));
        methods.put("POST", AnnotatedMethod.findMethod(obj, Post.class, exceptionHandlers));
        methods.put("PUT", AnnotatedMethod.findMethod(obj, Put.class, exceptionHandlers));
        // RFC 7231 §4.3.2: HEAD is GET without the body, and suppressing the body is the servlet
        // container's job. Not advertised in Allow -- see allowHeader.
        methods.put("HEAD", methods.get("GET"));
        final String allow = allowHeader(methods);
        return new Handler() {
            @Override
            public Promise<Response, NeverThrowsException> handle(Context context, Request request) {
                AnnotatedMethod method = methods.get(getMethod(request));
                if (method == null) {
                    // An unmapped HTTP verb (e.g. PATCH) yields a 405, with a body whose code
                    // matches the 405 status line. This mirrors AnnotatedMethod's mapped-verb-with-
                    // no-method sentinel, so both "method not allowed" paths render one shape rather
                    // than the status-line-405/body-code-501 mismatch a NotSupportedException gave.
                    Response response = new Response(Status.METHOD_NOT_ALLOWED);
                    response.setEntity(AnnotatedMethod.crestBody(ResourceException.newResourceException(
                            Status.METHOD_NOT_ALLOWED.getCode(), Status.METHOD_NOT_ALLOWED.getReasonPhrase())));
                    return newResultPromise(withAllow(response, allow));
                }

                try {
                    return method.invoke(context, request)
                            .then(new Function<Response, Response, NeverThrowsException>() {
                                @Override
                                public Response apply(Response response) {
                                    return withAllow(response, allow);
                                }
                            });
                } catch (Throwable t) {
                    DEBUG.error("Endpoints :: Caught exception during execution of handle() : ", t);
                    Response response = new Response(Status.INTERNAL_SERVER_ERROR);
                    response.setEntity(AnnotatedMethod.crestBody(new InternalServerErrorException(t)));
                    return newResultPromise(response);
                }
            }
        };
    }

    /**
     * Convenience method that produces a {@code Handler} using the {@link #from(Object)} method
     * and an object obtained from Guice.
     * @param cls The class to use.
     * @return A new {@code Handler}.
     */
    public static Handler from(Class<?> cls) {
        return from(Key.get(cls));
    }

    /**
     * Convenience method that produces a {@code Handler} using the {@link #from(Object)} method
     * and an object obtained from Guice.
     * @param key The Guice key to use.
     * @return A new {@code Handler}.
     */
    public static Handler from(Key key) {
        return from(InjectorHolder.getInstance(key));
    }

    /**
     * The verbs the endpoint actually implements, ready for the {@code Allow} header.
     * <p>
     * Derived from the resolved {@link AnnotatedMethod}s rather than from an annotation scan,
     * because {@code findMethod} also matches by method name -- a method literally called
     * {@code get} is dispatched to, but carries no {@code @Get} for a scan to find.
     * <p>
     * {@code HEAD} is deliberately absent even though it is mapped: Restlet answered {@code HEAD}
     * while advertising the mapped verbs only, and the recorded wire contract asserts that set.
     */
    private static String allowHeader(Map<String, AnnotatedMethod> methods) {
        List<String> supported = new ArrayList<>();
        for (String verb : MAPPED_VERBS) {
            if (methods.get(verb).isSupported()) {
                supported.add(verb);
            }
        }
        return String.join(", ", supported);
    }

    /**
     * Stamps {@code Allow}, which RFC 7231 §6.5.5 makes mandatory on a 405. Every response leaves
     * the handler through here, so this covers both of the framework's 405 producers -- the
     * unmapped verb above and {@link AnnotatedMethod}'s null-method sentinel -- in one place, and
     * leaves alone a handler that answered 405 with an {@code Allow} of its own.
     */
    private static Response withAllow(Response response, String allow) {
        if (Status.METHOD_NOT_ALLOWED.equals(response.getStatus())
                && response.getHeaders().get(HEADER_ALLOW) == null) {
            response.getHeaders().put(HEADER_ALLOW, allow);
        }
        return response;
    }

    /**
     * Returns the effective method name for an HTTP request taking into account
     * the "X-HTTP-Method-Override" header.
     *
     * @param req
     *            The HTTP request.
     * @return The effective method name.
     */
    private static String getMethod(org.forgerock.http.protocol.Request req) {
        String method = req.getMethod();
        if ("POST".equals(method)
                && req.getHeaders().getFirst(HEADER_X_HTTP_METHOD_OVERRIDE) != null) {
            method = req.getHeaders().getFirst(HEADER_X_HTTP_METHOD_OVERRIDE);
        }
        return method;
    }

    private Endpoints() {
    }
}
