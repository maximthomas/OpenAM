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
package org.openidentityplatform.openam.oauth2.http;

import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.forgerock.json.JsonValue;

/**
 * Data models for the ten shipping FreeMarker templates, each derived from the code that actually
 * populates it today rather than hand-invented.
 * <p>
 * Deriving rather than inventing is a deliberate decision, not fussiness. Both legs of
 * {@code RestletRendererParityTest} are fed the same model, so a fictional model still passes the
 * {@code Restlet == CHF} assert — the parity leg is structurally incapable of noticing. The golden
 * files' second job, however, is to be the regression guard that outlives Restlet's deletion, and a
 * golden built from a shape production never emits guards nothing at all, permanently and
 * unfalsifiably.
 * <p>
 * Three keys have types that the natural guess gets wrong, which is what makes this concrete:
 * <ul>
 *   <li>{@code display_scopes} / {@code display_claims} are JSON <em>text</em>, not collections —
 *       {@code ConsentRequiredResource:139,152} store {@code JsonValue.toString()}. The templates
 *       interpolate them raw ({@code displayScopes: ${display_scopes}}) straight into a JavaScript
 *       array literal. A {@code List} fails with "expected a string ... evaluated to a sequence".</li>
 *   <li>{@code valid_session} is a {@code String}, not a {@code Boolean} —
 *       {@code OpenIDConnectCheckSessionEndpoint:116} stores {@code validSession.toString()}, and
 *       {@code page/checkSession.ftl:56} applies {@code ?js_string}, which refuses a real boolean.</li>
 *   <li>{@code saveConsentEnabled} <em>is</em> a real {@code Boolean} ({@code AuthorizationService:205}
 *       via {@code ConsentRequiredResource:96}), because {@code page/authorize.ftl:59} tests it with
 *       {@code <#if saveConsentEnabled >} rather than {@code ??}.</li>
 * </ul>
 * The JSON-text values below are produced by running the same {@code JsonValue} calls the producer
 * runs, so the text is whatever {@code JsonValue} genuinely emits instead of a hand-copied guess.
 */
final class RendererFixtures {

    /**
     * Non-ASCII lives only in keys that reach the output unescaped. {@code ConsentRequiredResource:88-89}
     * pushes {@code display_name}/{@code display_description} through {@code ESAPI.encoder().encodeForHTML},
     * which would fold any high character back into an ASCII entity and silently defeat the UTF-8 byte
     * assertions this value exists to support. {@code user_name} ({@code :91}) is stored raw, and
     * {@code ?js_string} escapes JavaScript syntax without touching non-ASCII, so it survives to the bytes.
     */
    static final String NON_ASCII_USER_NAME = "Démø Üser Учётная";

    private RendererFixtures() {
    }

    /**
     * The consent-page model, from {@code ConsentRequiredResource.getDataModel}. Shared by all four
     * display folders: the producer does not vary by display — only the templates differ in which keys
     * they read (only {@code page/authorize.ftl} reads {@code saveConsentEnabled}; only
     * {@code wap/authorize.ftl} reads the never-populated {@code display_scope}).
     */
    static Map<String, Object> authorize() {
        Map<String, Object> data = new HashMap<>();

        // ConsentRequiredResource:79-80 seeds the model from the Restlet request attributes and then
        // copies every query parameter over verbatim, which is where these OAuth2 params come from.
        data.put("realm", "/");
        data.put("redirect_uri", "https://rp.example.com/callback");
        data.put("scope", "openid profile email");
        data.put("state", "af0ifjsldkj");
        data.put("nonce", "n-0S6_WzA2Mj");
        data.put("acr", "urn:mace:incommon:iap:silver");
        data.put("response_type", "code");
        data.put("client_id", "test_client_app");

        // ConsentRequiredResource:82-87 — resource-ref path, plus "?" + query when the query is non-blank.
        data.put("target", "/openam/oauth2/authorize?client_id=test_client_app&response_type=code");

        // :88-89 — already ESAPI-encoded by the producer, so these carry ESAPI's *output*. ESAPI leaves
        // alphanumerics and spaces untouched and turns "&" into "&amp;", which is what is written here.
        data.put("display_name", "Demo &amp; Co");
        data.put("display_description", "A demo client for the &quot;consent&quot; page");

        data.put("user_name", NON_ASCII_USER_NAME);         // :91 — raw, no ESAPI. See NON_ASCII_USER_NAME.
        data.put("xui", Boolean.TRUE);                      // :92 — produced, though no template reads it.
        data.put("user_code", "BDWD-HQPK");                 // :93 — set on the device flow, null otherwise.
        data.put("baseUrl", "https://openam.example.com:8443/openam");   // :94-95
        data.put("saveConsentEnabled", Boolean.TRUE);       // :96 — a real Boolean, see class javadoc.
        data.put("csrf", "1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809");        // :100
        data.put("locale", "en");                           // :105 — joined accepted languages.

        addDisplayScopesAndClaims(data);
        return data;
    }

    /**
     * Mirrors {@code ConsentRequiredResource.addDisplayScopesAndClaims:110-153}, including its ordering:
     * the scope object is added to the array <em>before</em> {@code values} is put on it ({@code :119} then
     * {@code :123}), which works because {@code JsonValue.getObject()} hands back the live underlying map.
     * Reproduced rather than simplified so the emitted JSON text matches production exactly.
     */
    private static void addDisplayScopesAndClaims(Map<String, Object> data) {
        JsonValue scopes = json(array());

        JsonValue profile = json(object(field("name", "View your profile")));
        scopes.add(profile.getObject());

        JsonValue email = json(object(field("name", "View your email address")));
        scopes.add(email.getObject());
        LinkedHashMap<String, Object> emailClaims = new LinkedHashMap<>();
        emailClaims.put("Email address", "demo@example.com");
        email.put("values", emailClaims);

        data.put("display_scopes", scopes.toString());      // :139 — JSON text, not a collection.

        JsonValue claims = json(array());
        claims.add(object(
                field("name", "Full name"),
                field("values", "Demo User")));
        data.put("display_claims", claims.toString());      // :152 — JSON text, not a collection.
    }

    /**
     * The error-page model, from {@code ExceptionHandler:133-137}: every entry of
     * {@code OAuth2RestletException.asMap()} plus {@code realm} and {@code baseUrl}. {@code asMap()} always
     * carries {@code error} and adds {@code error_description}/{@code error_uri}/{@code state} only when
     * non-empty; all four are populated here so both optional template branches render. {@code state} is
     * emitted by the producer but read by no template.
     * <p>
     * The non-ASCII {@code error_description} is realistic (the message is localized) and reaches the output
     * through {@code ?js_string}, which does not escape non-ASCII.
     */
    static Map<String, Object> error() {
        Map<String, Object> data = new HashMap<>();
        data.put("error", "invalid_request");
        data.put("error_description", "Paramètre requis manquant : redirect_uri");
        data.put("error_uri", "https://openam.example.com/docs/errors#invalid_request");
        data.put("state", "af0ifjsldkj");
        data.put("realm", "/");
        data.put("baseUrl", "https://openam.example.com:8443/openam");
        return data;
    }

    /** From {@code OpenIDConnectCheckSessionEndpoint.getDataModel:112-118}. */
    static Map<String, Object> checkSession() {
        Map<String, Object> data = new HashMap<>();
        data.put("cookie_name", "iPlanetDirectoryPro");
        data.put("client_uri", "https://rp.example.com/check_session_iframe");
        data.put("valid_session", Boolean.TRUE.toString());     // :116 — a String, see class javadoc.
        data.put("baseUrl", "https://openam.example.com:8443/openam");
        return data;
    }

    /**
     * From {@code OAuth2Representation.getFormPostRepresentation:175-187}. {@code formValues} is
     * {@code AuthorizationToken.getToken()}, a {@code Map<String, String>}; the template iterates
     * {@code formValues?keys}.
     */
    static Map<String, Object> formPost() {
        Map<String, Object> data = new HashMap<>();
        data.put("redirectUri", "https://rp.example.com/callback");
        Map<String, String> formValues = new LinkedHashMap<>();
        formValues.put("code", "g0ZGZmNjVmOWI");
        formValues.put("state", "af0ifjsldkj");
        data.put("formValues", formValues);
        return data;
    }

    /**
     * From {@code DeviceCodeVerificationResource.getTemplateRepresentation:223-235}. {@code errorCode} is
     * the method's own argument: {@code "not_found"} on the failure paths ({@code :139,143}) and
     * {@code null} on the success paths ({@code :208,272}). Populated here so the optional branch renders.
     */
    static Map<String, Object> codeVerificationForm() {
        Map<String, Object> data = deviceCodeCommon();
        data.put("errorCode", "not_found");
        return data;
    }

    /**
     * Same producer as {@link #codeVerificationForm()}, reached via {@code :208} with a {@code null}
     * {@code errorCode}. {@code CodeThanks.ftl} reads no {@code errorCode} regardless.
     */
    static Map<String, Object> codeThanks() {
        Map<String, Object> data = deviceCodeCommon();
        data.put("errorCode", null);
        return data;
    }

    private static Map<String, Object> deviceCodeCommon() {
        Map<String, Object> data = new HashMap<>();
        data.put("baseUrl", "https://openam.example.com:8443/openam");
        data.put("locale", "en");
        data.put("realm", "/");
        return data;
    }

    /**
     * {@code popup/popup.ftl} reads exactly one key. In production it is never populated by a producer:
     * {@code OAuth2Representation:83} renders another template to a string and injects it. This model
     * covers the template standalone; the composed case is covered separately by the parity test.
     */
    static Map<String, Object> popup() {
        Map<String, Object> data = new HashMap<>();
        data.put("htmlCode", "<p>embedded " + NON_ASCII_USER_NAME + "</p>");
        return data;
    }
}
