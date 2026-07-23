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

import org.forgerock.audit.AuditException;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Entity;
import org.forgerock.http.protocol.Request;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.rest.audit.RestletBodyAuditor;
import org.restlet.data.CharacterSet;
import org.restlet.data.Language;
import org.restlet.data.MediaType;
import org.restlet.ext.jackson.JacksonRepresentation;
import org.restlet.representation.Representation;
import org.restlet.representation.StringRepresentation;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * The 3d-2 parity oracle. Feeds the same bytes to the legacy {@code RestletBodyAuditor} and the CHF
 * {@link HttpBodyAuditor} and asserts identical output — the only instrument that pins the CHF auditor to
 * observed legacy behaviour rather than to the design's belief about it. Runs while Restlet is on the classpath;
 * degrades to a plain characterization test (in {@code HttpBodyAuditorTest}) once Phase 5d deletes the Restlet leg.
 */
@SuppressWarnings("unchecked")
public class RestletAuditParityTest {

    // Non-ASCII, as ASCII escapes so the assertion is independent of this file's compile encoding (e-acute, ya, na).
    private static final String NON_ASCII = "éя纳";

    @DataProvider
    private Object[][] jsonCases() {
        return new Object[][]{
            {"normal", new String[]{"scope", "token_type"}, "{\"scope\":\"read write\",\"token_type\":\"Bearer\"}"},
            {"missing field omitted", new String[]{"scope", "token_type"}, "{\"scope\":\"read\"}"},
            {"only listed fields", new String[]{"scope"}, "{\"scope\":\"read\",\"client_secret\":\"shh\"}"},
            {"non-ascii value", new String[]{"username"}, "{\"username\":\"" + NON_ASCII + "\"}"},
            {"boolean and numeric (introspect)", new String[]{"active", "expires_in"},
                    "{\"active\":true,\"expires_in\":3599}"},
            {"empty json object", new String[]{"scope"}, "{}"},
        };
    }

    @Test(dataProvider = "jsonCases")
    public void chfJsonAuditorMatchesBothRestletJsonAuditors(String desc, String[] fields, String body)
            throws Exception {
        Object chf = chfJson(body, fields).getObject();

        assertThat(chf).as(desc + " - chf vs jacksonAuditor").isEqualTo(jacksonAudit(body, fields).getObject());
        assertThat(chf).as(desc + " - chf vs jsonAuditor").isEqualTo(jsonAudit(body, fields).getObject());
    }

    @Test
    public void emptyBodyYieldsEmptyObject() throws Exception {
        // Compared against the org.json jsonAuditor leg, which guards empty on the representation. The jackson leg
        // is skipped here: a production empty body is a truly-empty Representation (isEmpty()==true), which a
        // hand-built JacksonRepresentation wrapping "" cannot reproduce — it would try to parse "" and throw.
        JsonValue chf = chfJson("", "scope");

        assertThat((Map<String, Object>) chf.getObject()).isEmpty();
        assertThat(chf.getObject()).isEqualTo(jsonAudit("", "scope").getObject());
    }

    @Test
    public void explicitNullFieldDivergesFromRestletJsonAuditorOnly() throws Exception {
        // Documented quirk: org.json .opt returns JSONObject.NULL (emitted), Jackson .get returns null (omitted).
        // The collapsed CHF auditor reads a Jackson Map, so it matches jacksonAuditor (omits) and diverges from
        // jsonAuditor (emits) only for an explicitly-null field — a shape we deliberately do not reproduce.
        String body = "{\"scope\":null}";

        assertThat(chfJson(body, "scope").getObject()).isEqualTo(jacksonAudit(body, "scope").getObject());
        assertThat((Map<String, Object>) chfJson(body, "scope").getObject()).doesNotContainKey("scope");
        assertThat((Map<String, Object>) jsonAudit(body, "scope").getObject()).containsKey("scope");
    }

    @Test
    public void formAuditorMatchesRestletFormAuditor() throws Exception {
        String[] fields = {"grant_type", "scope"};
        String body = "grant_type=password&scope=read%20write&client_secret=shh";
        JsonValue chf = HttpBodyAuditor.formAuditor(fields).apply(chfEntity(body, "application/x-www-form-urlencoded"));
        JsonValue restlet = (JsonValue) RestletBodyAuditor.formAuditor(fields).apply(restletForm(body));

        assertThat(chf.getObject()).isEqualTo(restlet.getObject());
    }

    @Test
    public void formAuditorParsesCharsetSuffixedContentType() throws Exception {
        // Unlike getForm()/fromRequestEntity, formAuditor uses fromFormString, so a ;charset=UTF-8 body is parsed.
        JsonValue chf = HttpBodyAuditor.formAuditor("scope")
                .apply(chfEntity("scope=read", "application/x-www-form-urlencoded;charset=UTF-8"));
        assertThat((Map<String, Object>) chf.getObject()).containsEntry("scope", "read");
    }

    private JsonValue chfJson(String body, String... fields) throws AuditException {
        return HttpBodyAuditor.jsonAuditor(fields).apply(chfEntity(body, "application/json"));
    }

    // Raw RestletBodyAuditor erases apply()'s "throws AuditException" to "throws Exception".
    private JsonValue jacksonAudit(String body, String... fields) throws Exception {
        return (JsonValue) RestletBodyAuditor.jacksonAuditor(fields).apply(restletJackson(body));
    }

    private JsonValue jsonAudit(String body, String... fields) throws Exception {
        return (JsonValue) RestletBodyAuditor.jsonAuditor(fields).apply(restletJson(body));
    }

    private Entity chfEntity(String body, String contentType) {
        Request request = new Request();
        request.getHeaders().put(ContentTypeHeader.valueOf(contentType));
        request.getEntity().setBytes(body.getBytes(UTF_8));
        return request.getEntity();
    }

    private Representation restletJson(String body) {
        return new StringRepresentation(body, MediaType.APPLICATION_JSON, Language.DEFAULT, CharacterSet.UTF_8);
    }

    private Representation restletJackson(String body) {
        return new JacksonRepresentation<Map>(restletJson(body), Map.class);
    }

    private Representation restletForm(String body) {
        return new StringRepresentation(body, MediaType.APPLICATION_WWW_FORM, Language.DEFAULT, CharacterSet.UTF_8);
    }
}
