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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Entity;
import org.forgerock.http.protocol.Request;
import org.forgerock.json.JsonValue;
import org.testng.annotations.Test;

/**
 * Standalone characterization of {@link HttpBodyAuditor}. Duplicates the contract pinned by
 * {@code RestletAuditParityTest} without the Restlet dependency, so coverage survives the Phase 5d deletion.
 */
@SuppressWarnings("unchecked")
public class HttpBodyAuditorTest {

    @Test
    public void jsonAuditorSelectsListedNonNullFieldsInFieldOrder() throws Exception {
        JsonValue result = HttpBodyAuditor.jsonAuditor("token_type", "scope")
                .apply(jsonEntity("{\"scope\":\"read\",\"token_type\":\"Bearer\",\"client_secret\":\"shh\"}"));

        assertThat(result.keys()).containsExactly("token_type", "scope"); // fields order, unlisted omitted
        assertThat(result.get("scope").asString()).isEqualTo("read");
    }

    @Test
    public void jsonAuditorOmitsMissingField() throws Exception {
        JsonValue result = HttpBodyAuditor.jsonAuditor("scope", "token_type").apply(jsonEntity("{\"scope\":\"read\"}"));

        assertThat(result.keys()).containsExactly("scope");
    }

    @Test
    public void jsonAuditorEmptyBodyYieldsEmptyObject() throws Exception {
        JsonValue result = HttpBodyAuditor.jsonAuditor("scope").apply(jsonEntity(""));

        assertThat((Map<String, Object>) result.getObject()).isEmpty();
    }

    @Test
    public void jsonAuditorPreservesNonStringValues() throws Exception {
        JsonValue result = HttpBodyAuditor.jsonAuditor("active", "expires_in")
                .apply(jsonEntity("{\"active\":true,\"expires_in\":3599}"));

        assertThat(result.get("active").getObject()).isEqualTo(Boolean.TRUE);
        assertThat(result.get("expires_in").asInteger()).isEqualTo(3599);
    }

    @Test
    public void formAuditorSelectsListedFields() throws Exception {
        JsonValue result = HttpBodyAuditor.formAuditor("grant_type", "scope")
                .apply(formEntity("grant_type=password&scope=read%20write&client_secret=shh"));

        assertThat((Map<String, Object>) result.getObject())
                .containsEntry("grant_type", "password")
                .containsEntry("scope", "read write") // %20 decoded
                .doesNotContainKey("client_secret");
    }

    @Test
    public void formAuditorParsesCharsetSuffixedBody() throws Exception {
        // formAuditor uses fromFormString, so it is not fooled by a ;charset=UTF-8 Content-Type (unlike getForm()).
        JsonValue result = HttpBodyAuditor.formAuditor("scope")
                .apply(entity("scope=read", "application/x-www-form-urlencoded;charset=UTF-8"));

        assertThat((Map<String, Object>) result.getObject()).containsEntry("scope", "read");
    }

    @Test
    public void noBodyAuditorReturnsNull() {
        assertThat(HttpBodyAuditor.noBodyAuditor()).isNull();
    }

    private Entity jsonEntity(String body) {
        return entity(body, "application/json");
    }

    private Entity formEntity(String body) {
        return entity(body, "application/x-www-form-urlencoded");
    }

    private Entity entity(String body, String contentType) {
        Request request = new Request();
        request.getHeaders().put(ContentTypeHeader.valueOf(contentType));
        request.getEntity().setBytes(body.getBytes(UTF_8));
        return request.getEntity();
    }
}
