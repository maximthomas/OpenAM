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
 * Portions Copyrighted 2026 3A Systems LLC.
 */
package org.forgerock.openam.audit;

import static java.util.Arrays.asList;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.audit.events.AccessAuditEventBuilder.ResponseStatus.SUCCESSFUL;
import static org.forgerock.openam.audit.AuditConstants.*;
import static org.forgerock.openam.audit.JsonUtils.*;

import org.forgerock.audit.events.AuditEvent;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.ClientContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @since 13.0.0
 */
public class AMAccessAuditEventBuilderTest {

    @Test
    public void canBuildAccessAuditEventWithContexts() throws Exception {
        AuditEvent accessEvent = new AMAccessAuditEventBuilder()
                .timestamp(1436389263629L)
                .eventName(EventName.AM_ACCESS_ATTEMPT)
                .component(Component.AUDIT)
                .transactionId("ad1f26e3-1ced-418d-b6ec-c8488411a625")
                .userId("id=amadmin,ou=user,dc=openam,dc=openidentityplatform,dc=org")
                .trackingId("12345")
                .client("172.16.101.7", 62375)
                .server("216.58.208.36", 80)
                .request("CREST", "READ")
                .httpRequest(false, "GET", "/some/path", getQueryParameters(), getHeaders())
                .response(SUCCESSFUL, "200", 42, MILLISECONDS)
                .toEvent();

        assertJsonValue(accessEvent.getValue(), "/access-event.json");
    }

    @Test
    public void canBuildAccessAuditEventWithContext() throws Exception {
        AuditEvent accessEvent = new AMAccessAuditEventBuilder()
                .timestamp(1436389263629L)
                .eventName(EventName.AM_ACCESS_ATTEMPT)
                .component(Component.AUDIT)
                .transactionId("ad1f26e3-1ced-418d-b6ec-c8488411a625")
                .userId("id=amadmin,ou=user,dc=openam,dc=openidentityplatform,dc=org")
                .trackingId("12345")
                .client("172.16.101.7", 62375)
                .server("216.58.208.36", 80)
                .request("CREST", "READ")
                .httpRequest(false, "GET", "/some/path", getQueryParameters(), getHeaders())
                .response(SUCCESSFUL, "200", 42, MILLISECONDS)
                .toEvent();

        assertJsonValue(accessEvent.getValue(), "/access-event.json");
    }

    @Test
    public void canHandleNullComponent() {
        AuditEvent accessEvent = new AMAccessAuditEventBuilder()
                .timestamp(1436389263629L)
                .eventName(EventName.AM_ACCESS_ATTEMPT)
                .transactionId("ad1f26e3-1ced-418d-b6ec-c8488411a625")
                .realm(null)
                .component(null)
                .toEvent();

        assertThat(accessEvent).isNotNull();
    }

    @DataProvider
    private Object[][] postBodies() {
        return new Object[][]{
            // content type, POST body. The first row is the D3 regression guard: getForm() would parse this
            // body and leak client_secret into queryParameters. The ;charset row (getForm's exact-match trap
            // already empties it) and the JSON row (getForm never parses JSON) characterize the query-only
            // contract but do not, by themselves, pin the fix — the plain form row does.
            {"application/x-www-form-urlencoded", "grant_type=password&client_secret=shh"},
            {"application/x-www-form-urlencoded;charset=UTF-8", "grant_type=password&client_secret=shh"},
            {"application/json", "{\"grant_type\":\"password\",\"client_secret\":\"shh\"}"},
        };
    }

    /**
     * D3 — forRequest must record URL query parameters only. A form-POST body (incl. client_secret)
     * must not leak into http/request/queryParameters, as request.getForm() would allow.
     */
    @Test(dataProvider = "postBodies")
    public void forRequestRecordsQueryParametersOnly(String contentType, String body) throws Exception {
        Context context = ClientContext.buildExternalClientContext(new RootContext())
                .remoteAddress("127.0.0.1")
                .remotePort(9000)
                .build();
        Request request = new Request()
                .setMethod("POST")
                .setUri(URI.create("http://example.com:8080/oauth2/access_token?q1=v1"));
        request.getHeaders().put(ContentTypeHeader.valueOf(contentType));
        request.getEntity().setString(body);

        AuditEvent event = new AMAccessAuditEventBuilder()
                .timestamp(1436389263629L)
                .eventName(EventName.AM_ACCESS_ATTEMPT)
                .transactionId("ad1f26e3-1ced-418d-b6ec-c8488411a625")
                .forRequest(request, context)
                .toEvent();

        JsonValue queryParameters = event.getValue().get("http").get("request").get("queryParameters");
        assertThat(queryParameters.keys()).containsOnly("q1");
    }

    private Map<String, List<String>> getQueryParameters() {
        HashMap<String, List<String>> queryParameters = new LinkedHashMap<>();
        queryParameters.put("p1", asList("v1"));
        queryParameters.put("p2", asList("v2"));
        return queryParameters;
    }

    private Map<String, List<String>> getHeaders() {
        HashMap<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("h1", asList("v1"));
        headers.put("h2", asList("v2"));
        headers.put("Cookie", asList("JSESSIONID=92F2583684E45A3612AAC1743FE70362; amlbcookie=01"));
        return headers;
    }

}

