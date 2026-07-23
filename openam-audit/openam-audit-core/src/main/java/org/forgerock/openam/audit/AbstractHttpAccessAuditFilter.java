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
 * Portions Copyrighted 2026 3A Systems LLC.
 */
package org.forgerock.openam.audit;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.forgerock.audit.events.AccessAuditEventBuilder.ResponseStatus.FAILED;
import static org.forgerock.audit.events.AccessAuditEventBuilder.ResponseStatus.SUCCESSFUL;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.audit.AMAuditEventBuilderUtils.getAllAvailableTrackingIds;
import static org.forgerock.openam.audit.AuditConstants.ACCESS_RESPONSE_DETAIL_REASON;
import static org.forgerock.openam.audit.AuditConstants.Component;
import static org.forgerock.openam.audit.AuditConstants.EventName;
import static org.forgerock.openam.utils.Time.*;

import java.util.Set;

import org.forgerock.audit.AuditException;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.Context;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.services.context.RequestAuditContext;
import org.forgerock.util.Function;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

import com.sun.identity.shared.debug.Debug;

/**
 * Responsible for logging access audit events for CHF requests.
 *
 * @since 13.0.0
 */
public abstract class AbstractHttpAccessAuditFilter implements Filter {

    private final Debug debug = Debug.getInstance("amAudit");

    private final AuditEventPublisher auditEventPublisher;
    private final AuditEventFactory auditEventFactory;
    private final Component component;

    /**
     * Create a new filter for the given component and handler.
     *
     * @param component The component for which events will be logged.
     * @param auditEventPublisher The publisher responsible for logging the events.
     * @param auditEventFactory The factory that can be used to create the events.
     */
    public AbstractHttpAccessAuditFilter(Component component,
            AuditEventPublisher auditEventPublisher, AuditEventFactory auditEventFactory) {
        this.auditEventPublisher = auditEventPublisher;
        this.auditEventFactory = auditEventFactory;
        this.component = component;
    }


    @Override
    public Promise<Response, NeverThrowsException> filter(final Context context, final Request request, Handler next) {
        auditAccessAttempt(request, context);
        return next.handle(context, request).then(new Function<Response, Response, NeverThrowsException>() {
            @Override
            public Response apply(Response response) {
                // D2: only 4xx/5xx are failures (Restlet parity). 3xx (e.g. OAuth2 authorize's 302) is a success.
                Status status = response.getStatus();
                if (status.isClientError() || status.isServerError()) {
                    auditAccessFailure(request, context, response);
                } else {
                    auditAccessSuccess(request, context, response);
                }
                return response;
            }
        });
    }

    private void auditAccessAttempt(Request request, Context context) {
        String realm = getRealm(context);
        if (auditEventPublisher.isAuditing(realm, AuditConstants.ACCESS_TOPIC, EventName.AM_ACCESS_ATTEMPT)) {

            AMAccessAuditEventBuilder builder = auditEventFactory.accessEvent(realm)
                    .timestamp(context.asContext(RequestAuditContext.class).getRequestReceivedTime())
                    .transactionId(AuditRequestContext.getTransactionIdValue())
                    .eventName(EventName.AM_ACCESS_ATTEMPT)
                    .component(component)
                    .userId(getUserIdForAccessAttempt(context, request))
                    .trackingIds(getTrackingIdsForAccessAttempt(context, request))
                    .forRequest(request, context);

            try {
                JsonValue detail = getRequestDetail(context, request);
                if (detail != null) {
                    builder.requestDetail(detail);
                }
                // tryPublish inside the try: a request-body parse failure skips the whole attempt event.
                auditEventPublisher.tryPublish(AuditConstants.ACCESS_TOPIC, builder.toEvent());
            } catch (AuditException e) {
                debug.error("Unable to create request detail for access attempt audit event", e);
            }
        }
    }

    private void auditAccessSuccess(Request request, Context context, Response response) {
        String realm = getRealm(context);
        if (auditEventPublisher.isAuditing(realm, AuditConstants.ACCESS_TOPIC, EventName.AM_ACCESS_OUTCOME)) {

            long endTime = currentTimeMillis();
            long elapsedTime = endTime - context.asContext(RequestAuditContext.class).getRequestReceivedTime();

            AMAccessAuditEventBuilder builder = auditEventFactory.accessEvent(realm)
                    .timestamp(endTime)
                    .transactionId(AuditRequestContext.getTransactionIdValue())
                    .eventName(EventName.AM_ACCESS_OUTCOME)
                    .component(component)
                    .userId(getUserIdForAccessOutcome(context, request, response))
                    .trackingIds(getTrackingIdsForAccessOutcome(context, request, response))
                    .forRequest(request, context);

            try {
                JsonValue detail = getResponseDetail(context, request, response);
                if (detail != null) {
                    builder.responseWithDetail(SUCCESSFUL, "", elapsedTime, MILLISECONDS, detail);
                } else {
                    builder.response(SUCCESSFUL, "", elapsedTime, MILLISECONDS);
                }
            } catch (AuditException e) {
                // Restlet parity: a response-body parse failure is swallowed; publish the outcome without detail.
                debug.warning("Unable to create response detail for access outcome audit event", e);
                builder.response(SUCCESSFUL, "", elapsedTime, MILLISECONDS);
            }

            auditEventPublisher.tryPublish(AuditConstants.ACCESS_TOPIC, builder.toEvent());
        }
    }

    private void auditAccessFailure(Request request, Context context, Response response) {
        String realm = getRealm(context);
        if (auditEventPublisher.isAuditing(realm, AuditConstants.ACCESS_TOPIC, EventName.AM_ACCESS_OUTCOME)) {

            long endTime = currentTimeMillis();
            String responseCode = Integer.toString(response.getStatus().getCode());
            long elapsedTime = endTime - context.asContext(RequestAuditContext.class).getRequestReceivedTime();
            JsonValue responseDetail = json(object(
                    field(ACCESS_RESPONSE_DETAIL_REASON, response.getStatus().getReasonPhrase())));

            AMAccessAuditEventBuilder builder = auditEventFactory.accessEvent(realm)
                    .timestamp(endTime)
                    .transactionId(AuditRequestContext.getTransactionIdValue())
                    .eventName(EventName.AM_ACCESS_OUTCOME)
                    .component(component)
                    .userId(getUserIdForAccessOutcome(context, request, response))
                    .trackingIds(getTrackingIdsForAccessOutcome(context, request, response))
                    .responseWithDetail(FAILED, responseCode, elapsedTime, MILLISECONDS, responseDetail)
                    .forRequest(request, context);

            auditEventPublisher.tryPublish(AuditConstants.ACCESS_TOPIC, builder.toEvent());
        }
    }

    /**
     * Retrieve the user ID for an access attempt.
     *
     * @param request the restlet request
     * @return the user ID
     */
    protected String getUserIdForAccessAttempt(Request request) {
        String userId = AuditRequestContext.getProperty(AuditConstants.USER_ID);
        return userId == null ? "" : userId;
    }

    /**
     * Retrieve the tracking IDs for an access attempt.
     *
     * @param request the restlet request
     * @return the tracking IDs
     */
    protected Set<String> getTrackingIdsForAccessAttempt(Request request) {
        return getAllAvailableTrackingIds();
    }

    /**
     * Retrieve the user ID for an access outcome.
     *
     * @param response the restlet response
     * @return the user ID
     */
    protected String getUserIdForAccessOutcome(Response response) {
        String userId = AuditRequestContext.getProperty(AuditConstants.USER_ID);
        return userId == null ? "" : userId;
    }

    /**
     * Retrieve the tracking IDs for an access outcome.
     *
     * @param response the restlet response
     * @return the tracking IDs
     */
    protected Set<String> getTrackingIdsForAccessOutcome(Response response) {
        return getAllAvailableTrackingIds();
    }

    /**
     * Context-bearing hooks. The base calls these; the defaults delegate to the request-only signatures so
     * existing subclasses keep working unchanged. Subclasses needing the context/request (e.g. OAuth2) override these.
     */
    protected String getUserIdForAccessAttempt(Context context, Request request) {
        return getUserIdForAccessAttempt(request);
    }

    protected Set<String> getTrackingIdsForAccessAttempt(Context context, Request request) {
        return getTrackingIdsForAccessAttempt(request);
    }

    protected String getUserIdForAccessOutcome(Context context, Request request, Response response) {
        return getUserIdForAccessOutcome(response);
    }

    protected Set<String> getTrackingIdsForAccessOutcome(Context context, Request request, Response response) {
        return getTrackingIdsForAccessOutcome(response);
    }

    /**
     * Body-detail hooks. Default to no detail. Both declare {@code AuditException} so the base owns Restlet's two
     * divergent policies (see {@link #filter}): a request-detail failure skips the whole attempt event, a
     * response-detail failure is swallowed to no-detail.
     */
    protected JsonValue getRequestDetail(Context context, Request request) throws AuditException {
        return null;
    }

    protected JsonValue getResponseDetail(Context context, Request request, Response response) throws AuditException {
        return null;
    }

    /**
     * Get the realm from the request context. If the realm is either {@code null} or empty the event will be published
     * to the default audit service.
     *
     * @param context The request context.
     * @return The realm.
     */
    protected abstract String getRealm(Context context);

}
