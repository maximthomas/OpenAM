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

import static org.forgerock.util.promise.Promises.newResultPromise;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.services.context.Context;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.util.Function;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

import com.sun.identity.shared.debug.Debug;

/**
 * A method annotated with one of {@link Get}, {@link Post}, {@link Put} or {@link Delete}. This class
 * works out what parameters are going to need to be passed to the annotated method, and creates
 * necessary functions for translating at reflection time so that reflection is not done at request
 * time.
 * <p>
 * This class is expected to only be used from the {@link Endpoints} class.
 * @since 13.0.0
 */
public class AnnotatedMethod {
    private final static Debug DEBUG = Debug.getInstance("frRest");
    private final Object requestHandler;
    private final Method method;
    private final int requestParameter;
    private final int numberOfParameters;
    private final String operation;
    private final Function<Object, Promise<Response, NeverThrowsException>, NeverThrowsException> responseAdapter;
    private final List<ContextParameter> contextParameters;
    /** Index of the parameter taking the thrown exception, or -1. Set for {@link ExceptionHandler} methods. */
    private final int exceptionParameter;
    /** The endpoint's exception handlers, keyed by the type each declares. Empty if it has none. */
    private final Map<Class<? extends Throwable>, AnnotatedMethod> exceptionHandlers;

    AnnotatedMethod(String operation, Object requestHandler, Method method, List<ContextParameter> contextParameters,
            int requestParameter, int numberOfParameters,
            Function<Object, Promise<Response, NeverThrowsException>, NeverThrowsException> responseAdapter) {
        this(operation, requestHandler, method, contextParameters, requestParameter, numberOfParameters,
                responseAdapter, -1, Collections.<Class<? extends Throwable>, AnnotatedMethod>emptyMap());
    }

    AnnotatedMethod(String operation, Object requestHandler, Method method, List<ContextParameter> contextParameters,
            int requestParameter, int numberOfParameters,
            Function<Object, Promise<Response, NeverThrowsException>, NeverThrowsException> responseAdapter,
            int exceptionParameter, Map<Class<? extends Throwable>, AnnotatedMethod> exceptionHandlers) {
        this.operation = operation;
        this.requestHandler = requestHandler;
        this.method = method;
        this.contextParameters = contextParameters;
        this.requestParameter = requestParameter;
        this.numberOfParameters = numberOfParameters;
        this.responseAdapter = responseAdapter;
        this.exceptionParameter = exceptionParameter;
        this.exceptionHandlers = exceptionHandlers;
    }

    Promise<Response, NeverThrowsException> invoke(Context context, Request request) {
        if (method == null) {
            Object entity = crestBody(ResourceException.getException(Status.METHOD_NOT_ALLOWED.getCode(),
                    Status.METHOD_NOT_ALLOWED.getReasonPhrase()));
            return newResultPromise(createErrorResponse(Status.METHOD_NOT_ALLOWED, entity));
        }
        try {
            return call(context, request, null);
        } catch (InvocationTargetException e) {
            // The annotated method's own throw, which the endpoint is entitled to map.
            return handleException(context, request, e.getCause());
        } catch (Throwable t) {
            // A failure of the framework's own plumbing: not the endpoint's to intercept.
            return defaultErrorResponse(t);
        }
    }

    /** Invokes the annotated method; {@code thrown} fills the exception parameter, if it has one. */
    private Promise<Response, NeverThrowsException> call(Context context, Request request, Throwable thrown)
            throws IllegalAccessException, InvocationTargetException {
        Object[] args = new Object[numberOfParameters];
        if (requestParameter > -1) {
            args[requestParameter] = request;
        }
        if (exceptionParameter > -1) {
            args[exceptionParameter] = thrown;
        }
        for (ContextParameter parameter : contextParameters) {
            args[parameter.index] = parameter.getContext(context);
        }
        return responseAdapter.apply(method.invoke(requestHandler, args));
    }

    /** Reflection wraps whatever the method threw; everything else is already the failure itself. */
    private static Throwable unwrap(Throwable t) {
        return t instanceof InvocationTargetException ? t.getCause() : t;
    }

    /**
     * Turns the exception a method threw into a response, using the endpoint's own
     * {@link ExceptionHandler} if one matches it.
     */
    private Promise<Response, NeverThrowsException> handleException(Context context, Request request, Throwable t) {
        AnnotatedMethod handler = mostSpecificExceptionHandler(t);
        if (handler != null) {
            try {
                // call, not invoke: an exception handler that throws must not be re-entered.
                return handler.call(context, request, t);
            } catch (Throwable failure) {
                DEBUG.error("Exception handler " + handler.method.getName() + " failed while handling: ", t);
                DEBUG.error("Exception handler failed with: ", unwrap(failure));
            }
        }
        return defaultErrorResponse(t);
    }

    /**
     * The framework's own answer to a failure: a CREST error carrying the throwable's message, so
     * that it reaches the client as a body rather than as an empty 500.
     */
    private Promise<Response, NeverThrowsException> defaultErrorResponse(Throwable t) {
        DEBUG.warning("Could not invoke method: ", t);
        Response response = new Response(Status.INTERNAL_SERVER_ERROR);
        response.setEntity(crestBody(new InternalServerErrorException(t)));
        // setCause takes an Exception, so an Error can only be kept by wrapping it.
        response.setCause(t instanceof Exception ? (Exception) t : new IllegalStateException(t));
        return newResultPromise(response);
    }

    /**
     * The CREST error body this framework puts on the wire, with {@code message} left as the
     * exception wrote it.
     * <p>
     * {@code ResourceException.toJsonValue()} runs {@code message} through Guava's HTML escaper,
     * because a CREST body is also rendered into HTML pages elsewhere. This writer emits
     * <em>JSON</em> -- {@code setEntity(Map)} routes to {@code setJson} -- so escaping here is the
     * wrong layer: it corrupts the value for every JSON client (a message naming
     * {@code response_type <foo>} arrives as {@code &lt;foo&gt;}) while protecting nobody, since a
     * consumer that renders it into HTML must escape at render time against its own context anyway.
     * Each of this module's consumers would otherwise have to reverse the transform for itself.
     *
     * @param e the exception to render.
     * @return the body, ready for {@code Response.setEntity}.
     */
    static Object crestBody(ResourceException e) {
        JsonValue json = e.toJsonValue();
        if (e.getMessage() != null) {
            json.put("message", e.getMessage());
        }
        return json.getObject();
    }

    /**
     * The handler whose declared type is closest to the thrown exception. Every candidate is a
     * supertype of the thrown class and so lies on its superclass chain, which makes "closest"
     * unambiguous.
     */
    private AnnotatedMethod mostSpecificExceptionHandler(Throwable t) {
        Class<? extends Throwable> match = null;
        for (Class<? extends Throwable> candidate : exceptionHandlers.keySet()) {
            if (candidate.isInstance(t) && (match == null || match.isAssignableFrom(candidate))) {
                match = candidate;
            }
        }
        return match == null ? null : exceptionHandlers.get(match);
    }

    private Response createErrorResponse(Status status, Object entity) {
        return new Response(status).setEntity(entity);
    }

    static AnnotatedMethod findMethod(Object requestHandler, Class<? extends Annotation> annotation,
            Map<Class<? extends Throwable>, AnnotatedMethod> exceptionHandlers) {
        for (Method method : requestHandler.getClass().getMethods()) {
            if (method.getAnnotation(annotation) != null) {
                AnnotatedMethod checked = checkMethod(annotation, requestHandler, method, exceptionHandlers);
                if (checked != null) {
                    return checked;
                }
            }
        }
        for (Method method : requestHandler.getClass().getMethods()) {
            String crestVerb = annotation.getSimpleName().toLowerCase();
            String methodName = method.getName();
            if (methodName.equals(crestVerb)) {
                AnnotatedMethod checked = checkMethod(annotation, requestHandler, method, exceptionHandlers);
                if (checked != null) {
                    return checked;
                }
            }
        }
        return new AnnotatedMethod(annotation.getSimpleName(), null, null, null, -1, -1, null);
    }

    /**
     * Collects the object's {@link ExceptionHandler} methods, keyed by the exception type each
     * declares. Scanned once, when the endpoint is mounted.
     */
    static Map<Class<? extends Throwable>, AnnotatedMethod> findExceptionHandlers(Object requestHandler) {
        Map<Class<? extends Throwable>, AnnotatedMethod> handlers = new LinkedHashMap<>();
        for (Method method : requestHandler.getClass().getMethods()) {
            if (method.getAnnotation(ExceptionHandler.class) == null) {
                continue;
            }
            AnnotatedMethod handler = checkMethod(ExceptionHandler.class, requestHandler, method,
                    Collections.<Class<? extends Throwable>, AnnotatedMethod>emptyMap());
            if (handler.exceptionParameter < 0) {
                throw new IllegalArgumentException("@ExceptionHandler method " + method.getName()
                        + " must take one unannotated parameter assignable to Throwable");
            }
            Class<? extends Throwable> type = method.getParameterTypes()[handler.exceptionParameter]
                    .asSubclass(Throwable.class);
            if (handlers.put(type, handler) != null) {
                throw new IllegalArgumentException("More than one @ExceptionHandler for " + type);
            }
        }
        return handlers;
    }

    static AnnotatedMethod checkMethod(Class<?> annotation, Object requestHandler, Method method,
            Map<Class<? extends Throwable>, AnnotatedMethod> exceptionHandlers) {
        List<ContextParameter> contextParams = new ArrayList<>();
        int requestParam = -1;
        int exceptionParam = -1;
        for (int i = 0; i < method.getParameterTypes().length; i++) {
            Class<?> type = method.getParameterTypes()[i];
            boolean contextual = false;
            for (Annotation paramAnnotation : method.getParameterAnnotations()[i]) {
                if (paramAnnotation instanceof Contextual) {
                    contextual = true;
                    if (Context.class.isAssignableFrom(type)) {
                        contextParams.add(new ContextParameter(i, (Class<? extends Context>) type));
                    } else if (Request.class.isAssignableFrom(type)) {
                        requestParam = i;
                    }
                }
            }
            if (!contextual && Throwable.class.isAssignableFrom(type)) {
                if (exceptionParam < 0) {
                    exceptionParam = i;
                } else if (ExceptionHandler.class.equals(annotation)) {
                    // Only one of them could ever be filled, so for a handler this is a mistake.
                    throw new IllegalArgumentException("More than one Throwable parameter on " + method.getName());
                }
            }
        }
        String contentType = checkContentType(method);
        Function<Object, Promise<Response, NeverThrowsException>, NeverThrowsException> resourceCreator;
        if (Promise.class.equals(method.getReturnType())) {
            checkPromiseType(method);
            resourceCreator = new PromisedResponseCreator();
        } else if (Response.class.equals(method.getReturnType())) {
            resourceCreator = new Function<Object, Promise<Response, NeverThrowsException>, NeverThrowsException>() {
                @Override
                public Promise<Response, NeverThrowsException> apply(Object o) {
                    return newResultPromise((Response) o);
                }
            };
        } else {
            resourceCreator = ResponseCreator.forType(method.getReturnType(), contentType);
        }
        return new AnnotatedMethod(annotation.getSimpleName(), requestHandler, method, contextParams,
                requestParam, method.getParameterTypes().length, resourceCreator, exceptionParam, exceptionHandlers);
    }

    /**
     * The content type the method declares with {@link Produces}, or null. A method that builds
     * its own {@code Response} owns its headers, and a {@code JsonValue} entity writes its own
     * {@code application/json}, so declaring anything else there is a contradiction rather than
     * an instruction, and is rejected while there is still someone to tell.
     */
    private static String checkContentType(Method method) {
        Produces produces = method.getAnnotation(Produces.class);
        if (produces == null) {
            return null;
        }
        String contentType = produces.value();
        Class<?> returnType = method.getReturnType();
        if (Response.class.equals(returnType) || Promise.class.equals(returnType)) {
            throw new IllegalArgumentException("@Produces is not supported on " + method.getName()
                    + ", which returns its own " + returnType.getSimpleName());
        }
        if (Void.class.equals(returnType)) {
            throw new IllegalArgumentException("@Produces is not supported on " + method.getName()
                    + ", which never has content to describe");
        }
        ContentTypeHeader header = parseContentType(contentType, method);
        if (JsonValue.class.equals(returnType) && !producesJson(header)) {
            throw new IllegalArgumentException("@Produces(\"" + contentType + "\") on " + method.getName()
                    + " contradicts the application/json; charset=UTF-8 its JsonValue return produces");
        }
        if (String.class.equals(returnType) && header.getCharset() == null) {
            // Entity encodes a String with the charset the message declares, and falls back to
            // ISO-8859-1 when it declares none - which is the defect this annotation must not reopen.
            return contentType + "; charset=" + StandardCharsets.UTF_8.name();
        }
        return contentType;
    }

    private static boolean producesJson(ContentTypeHeader header) {
        return "application/json".equalsIgnoreCase(header.getType())
                && (header.getCharset() == null || StandardCharsets.UTF_8.equals(header.getCharset()));
    }

    private static ContentTypeHeader parseContentType(String contentType, Method method) {
        ContentTypeHeader header;
        try {
            header = ContentTypeHeader.valueOf(contentType);
            header.getCharset();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unusable @Produces(\"" + contentType + "\") on "
                    + method.getName(), e);
        }
        if (header.getType() == null) {
            throw new IllegalArgumentException("Empty @Produces on " + method.getName());
        }
        return header;
    }

    /**
     * Erasure hides a {@code Promise}'s type arguments from {@code getReturnType()}, so they are
     * checked against the generic return type — here, at wiring time, rather than as a cast
     * failure on every request.
     */
    private static void checkPromiseType(Method method) {
        Type returnType = method.getGenericReturnType();
        if (returnType instanceof ParameterizedType) {
            Type[] arguments = ((ParameterizedType) returnType).getActualTypeArguments();
            if (arguments.length == 2 && Response.class.equals(arguments[0])
                    && NeverThrowsException.class.equals(arguments[1])) {
                return;
            }
        }
        throw new IllegalArgumentException("Unsupported response type: " + returnType);
    }

    private static final String DEFAULT_TEXT_CONTENT_TYPE = "text/plain; charset=UTF-8";

    /**
     * A function to create a {@link Response} from the generic type of a method that produces response
     * content.
     */
    private final static class ResponseCreator
            implements Function<Object, Promise<Response, NeverThrowsException>, NeverThrowsException> {

        private final Function<Object, Object, NeverThrowsException> entityConverter;
        private final String contentType;

        private ResponseCreator(Function<Object, Object, NeverThrowsException> entityConverter, String contentType) {
            this.entityConverter = entityConverter;
            this.contentType = contentType;
        }

        @Override
        public Promise<Response, NeverThrowsException> apply(Object o) {
            Object content = entityConverter.apply(o);
            if (content == null) {
                // Nothing to send: setEntity(null) would write a JSON "null" and its content type.
                return newResultPromise(new Response(Status.NO_CONTENT));
            }
            Response response = new Response(Status.OK);
            if (contentType != null) {
                // Before the entity: Entity encodes a String with the charset the message declares.
                response.getHeaders().put(ContentTypeHeader.NAME, contentType);
            }
            return newResultPromise(response.setEntity(content));
        }

        /**
         * Uses reflection to deduce the need for a {@code ResourceCreator}, and return an appropriately created one
         * if needed.
         * @param type The type for the {@code Response} entity.
         * @param contentType The content type the method declares, or null.
         * @return A new function.
         */
        private static Function<Object, Promise<Response, NeverThrowsException>, NeverThrowsException> forType(
                Class<?> type, String contentType) {
            if (String.class.equals(type) || Void.class.equals(type) || byte[].class.equals(type)) {
                // Only text gets a default: the framework cannot say what arbitrary bytes are.
                return new ResponseCreator(IDENTITY_FUNCTION,
                        contentType == null && String.class.equals(type) ? DEFAULT_TEXT_CONTENT_TYPE : contentType);
            } else if (JsonValue.class.equals(type)) {
                // The entity writes application/json itself; @Produces cannot disagree by now.
                return new ResponseCreator(new Function<Object, Object, NeverThrowsException>() {
                    @Override
                    public Object apply(Object o) {
                        return ((JsonValue) o).getObject();
                    }
                }, null);
            }
            throw new IllegalArgumentException("Unsupported response type: " + type);
        }

    }

    private static class PromisedResponseCreator
            implements Function<Object, Promise<Response, NeverThrowsException>, NeverThrowsException> {

        @SuppressWarnings("unchecked")
        @Override
        public Promise<Response, NeverThrowsException> apply(Object o) {
            // A null promise means no response to send, as a null entity does.
            return o == null
                    ? newResultPromise(new Response(Status.NO_CONTENT))
                    : (Promise<Response, NeverThrowsException>) o;
        }
    }

    //@Checkstyle:off
    private static final Function<Object, Object, NeverThrowsException> IDENTITY_FUNCTION =
            new Function<Object, Object, NeverThrowsException>() {
        @Override
        public Object apply(Object o) {
            return o;
        }
    };
    //@Checkstyle:on

    private final static class ContextParameter {
        private final int index;
        private final Class<? extends Context> type;

        private ContextParameter(int index, Class<? extends Context> type) {
            this.index = index;
            this.type = type.equals(Context.class) ? null : type;
        }

        private Context getContext(Context context) {
            return type == null ? context : context.asContext(type);
        }
    }
}
