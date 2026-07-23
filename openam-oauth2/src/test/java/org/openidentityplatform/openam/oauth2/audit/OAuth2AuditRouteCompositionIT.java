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

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.openam.audit.AuditConstants.EventName.AM_ACCESS_ATTEMPT;
import static org.forgerock.openam.audit.AuditConstants.EventName.AM_ACCESS_OUTCOME;
import static org.forgerock.openam.audit.AuditConstants.TrackingIdKey.OAUTH2_ACCESS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.net.URI;
import java.util.List;

import org.forgerock.audit.events.AuditEvent;
import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.IntrospectableToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.openam.audit.AuditConstants;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.services.context.ClientContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RequestAuditContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.Promises;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.iplanet.sso.SSOToken;

/**
 * Drives {@link OAuth2HttpAccessAuditFilter} over a real CHF chain, in process — the earliest point the
 * build-ahead risk can be retired for the audit layer (Phase 4/5 wires it to a live route). Proves the filter
 * composes: two events, body detail, token-derived identity, the 3xx-is-success classification, and that reading
 * the response body in the auditor leaves it intact on the wire.
 *
 * <p>{@code *IT.java} is bound to failsafe, so {@code mvn -pl openam-oauth2 test} does not run this class; it
 * needs {@code mvn -pl openam-oauth2 verify}.
 */
public class OAuth2AuditRouteCompositionIT {

    private static final String JSON_BODY = "{\"scope\":\"read\",\"token_type\":\"Bearer\"}";

    @BeforeMethod
    public void setUp() {
        AuditRequestContext.clear();
    }

    @AfterMethod
    public void tearDown() {
        AuditRequestContext.clear();
    }

    @Test
    public void formPostWithTokenProducesTwoEventsWithDetailAndIdentity() throws Exception {
        AuditEventPublisher publisher = auditingPublisher();
        Handler chain = Handlers.chainOf(jsonHandler(Status.OK, JSON_BODY),
                oauth2Filter(publisher,
                        HttpBodyAuditor.formAuditor("grant_type", "client_id"),
                        HttpBodyAuditor.jsonAuditor("scope", "token_type")));

        Response response = chain.handle(auditContext(), formRequest()).getOrThrowUninterruptibly();

        List<AuditEvent> events = captureTwoEvents(publisher);
        JsonValue attempt = events.get(0).getValue();
        JsonValue outcome = events.get(1).getValue();

        // 1. attempt then outcome
        assertThat(attempt.get("eventName").asString()).isEqualTo(AM_ACCESS_ATTEMPT.toString());
        assertThat(outcome.get("eventName").asString()).isEqualTo(AM_ACCESS_OUTCOME.toString());
        // 2. request/detail from the form body; response/detail from the json body
        assertThat(attempt.get("request").get("detail").get("grant_type").asString()).isEqualTo("password");
        assertThat(attempt.get("request").get("detail").get("client_id").asString()).isEqualTo("myclient");
        assertThat(outcome.get("response").get("detail").get("scope").asString()).isEqualTo("read");
        // 3. identity/tracking from the token
        assertThat(attempt.get("userId").asString()).isEqualTo("resource-owner");
        assertThat(attempt.get("trackingIds").asList(String.class)).contains("track-access");
        // 5. response body still intact on the returned Response after the auditor read it
        assertThat(response.getEntity().getString()).isEqualTo(JSON_BODY);
    }

    @Test
    public void redirect302OutcomeIsAuditedSuccessful() throws Exception {
        // 4. A 302 handler response audits SUCCESSFUL, not FAILED.
        AuditEventPublisher publisher = auditingPublisher();
        Handler chain = Handlers.chainOf(jsonHandler(Status.FOUND, ""),
                oauth2Filter(publisher, HttpBodyAuditor.noBodyAuditor(), HttpBodyAuditor.noBodyAuditor()));

        chain.handle(auditContext(), formRequest()).getOrThrowUninterruptibly();

        JsonValue outcome = captureTwoEvents(publisher).get(1).getValue();
        assertThat(outcome.get("eventName").asString()).isEqualTo(AM_ACCESS_OUTCOME.toString());
        assertThat(outcome.get("response").get("status").asString()).isEqualTo("SUCCESSFUL");
    }

    private AuditEventPublisher auditingPublisher() {
        AuditEventPublisher publisher = mock(AuditEventPublisher.class);
        given(publisher.isAuditing(any(), any(), any())).willReturn(true);
        return publisher;
    }

    private OAuth2HttpAccessAuditFilter oauth2Filter(AuditEventPublisher publisher,
            HttpBodyAuditor requestDetail, HttpBodyAuditor responseDetail) {
        OAuth2RequestFactory requestFactory = mock(OAuth2RequestFactory.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        IntrospectableToken token = mock(IntrospectableToken.class);
        given(token.getResourceOwnerId()).willReturn("resource-owner");
        given(token.getAuditTrackingIdKey()).willReturn(OAUTH2_ACCESS);
        given(token.getAuditTrackingId()).willReturn("track-access");
        given(oAuth2Request.getTokens()).willReturn(singletonList(token));
        given(requestFactory.create(any(Context.class), any(Request.class))).willReturn(oAuth2Request);
        return new OAuth2HttpAccessAuditFilter(publisher, new AuditEventFactory(), requestFactory,
                requestDetail, responseDetail) {
            @Override
            protected SSOToken getSSOToken(OAuth2Request oAuth2Request) {
                return null; // real SSOTokenManager cannot run in-process; the token supplies identity
            }
        };
    }

    private Handler jsonHandler(Status status, String body) {
        return (context, request) -> {
            Response response = new Response(status);
            response.getHeaders().put(ContentTypeHeader.valueOf("application/json"));
            response.getEntity().setString(body);
            return Promises.newResultPromise(response);
        };
    }

    private Context auditContext() {
        return new RequestAuditContext(ClientContext.buildExternalClientContext(new RootContext())
                .remoteAddress("127.0.0.1")
                .remotePort(9000)
                .build());
    }

    private Request formRequest() {
        Request request = new Request().setMethod("POST")
                .setUri(URI.create("http://openam.example:8080/oauth2/access_token"));
        request.getHeaders().put(ContentTypeHeader.valueOf("application/x-www-form-urlencoded"));
        request.getEntity().setString("grant_type=password&client_id=myclient&client_secret=shh");
        return request;
    }

    private List<AuditEvent> captureTwoEvents(AuditEventPublisher publisher) {
        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(publisher, times(2)).tryPublish(eq(AuditConstants.ACCESS_TOPIC), captor.capture());
        return captor.getAllValues();
    }
}
