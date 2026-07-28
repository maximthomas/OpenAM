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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import freemarker.template.TemplateException;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.CsrfProtection;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2Utils;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.xui.XUIState;
import org.forgerock.util.annotations.VisibleForTesting;
import org.owasp.esapi.ESAPI;

/**
 * Renders the OAuth2 consent page -- the CHF port of {@code ConsentRequiredResource.getDataModel} plus its
 * {@code authorize.ftl} render.
 *
 * <p><strong>A collaborator, not a base class.</strong> On Restlet the consent page was shared with the device
 * flow by inheritance ({@code DeviceCodeVerificationResource extends ConsentRequiredResource}). On CHF the
 * superclass slot belongs to {@link AbstractOAuth2HttpBrowserEndpoint}, whose {@code @ExceptionHandler} must
 * not be displaced, and Java has single inheritance -- so the sharing mechanism becomes composition. Injected
 * into {@code AuthorizeHandler} and, unchanged, into 5b-2's device-flow handler.
 */
@Singleton
public class ConsentPageRenderer {

    /**
     * The OAuth2 parameters Restlet copied <em>implicitly</em>, read by phases 1 and 2 alike. Restlet had two
     * bulk copies, not one: the request attributes and then the query map. On {@code /authorize} only the
     * second carries anything; on the device flow only the first does, because the handler seeds the whole
     * device-code record into the attributes and the consent form is posted back with no query at all (D2).
     *
     * <p>Enumerated here because CHF has no equivalent bulk copy, and a missing name is invisible: the
     * template's {@code <#if x??>} simply goes false and the field vanishes from the page (R-5b1.2).
     */
    private static final List<String> MODEL_KEYS = List.of(
            OAuth2Constants.Custom.REALM,
            OAuth2Constants.Params.REDIRECT_URI,
            OAuth2Constants.Params.SCOPE,
            OAuth2Constants.Params.STATE,
            OAuth2Constants.Custom.NONCE,
            // The query parameter is "acr", not the request's "acr_values": the templates read ${acr}, and
            // the producer only ever had whatever the query literally carried.
            OAuth2Constants.JWTTokenParams.ACR,
            OAuth2Constants.Params.RESPONSE_TYPE,
            OAuth2Constants.Params.CLIENT_ID,
            OAuth2Constants.Custom.UI_LOCALES);

    private final FreemarkerTemplateRenderer renderer;
    private final XUIState xuiState;
    private final BaseURLProviderFactory baseURLProviderFactory;
    private final CsrfProtection csrfProtection;

    @Inject
    ConsentPageRenderer(FreemarkerTemplateRenderer renderer, XUIState xuiState,
            BaseURLProviderFactory baseURLProviderFactory, CsrfProtection csrfProtection) {
        this.renderer = renderer;
        this.xuiState = xuiState;
        this.baseURLProviderFactory = baseURLProviderFactory;
        this.csrfProtection = csrfProtection;
    }

    /**
     * The consent page at 200, rendered for the request's {@code ?display=}.
     *
     * @param consentRequired the details for requesting consent.
     * @param o2 the OAuth2 request.
     * @param request the CHF request, whose URI supplies the form's post-back target.
     * @return the rendered page.
     * @throws IllegalArgumentException if {@code ?display=} names no known display. Deliberately allowed to
     *     escape: the caller maps it to {@code 400 invalid_request} (D7), because defaulting an unknown
     *     display to {@code page} would turn a rejected request into a rendered consent page.
     * @throws IOException if the template cannot be found or read.
     * @throws TemplateException if the template fails to render.
     */
    public Response render(ResourceOwnerConsentRequired consentRequired, OAuth2Request o2, Request request)
            throws IOException, TemplateException {
        String html = renderer.renderForDisplay(o2.getParameter(OAuth2Constants.Custom.DISPLAY),
                "authorize.ftl", dataModel(consentRequired, o2, request));
        return FreemarkerTemplateRenderer.toHtmlResponse(Status.OK, html);
    }

    /**
     * Builds the model in the producer's three phases, <strong>in order</strong>. The order is behaviour, not
     * style: phase 2 overlays phase 1 (so a raw {@code ?realm=} beats the router-resolved realm, as it does
     * today), and phase 3 must follow phase 2 so a client cannot supply its own {@code display_scope}
     * (CVE-2026-62280).
     *
     * @return the data model; package-private so the golden assert can drive it without a {@code Response}.
     */
    @VisibleForTesting
    Map<String, Object> dataModel(ResourceOwnerConsentRequired consentRequired, OAuth2Request o2,
            Request request) {
        // 1. Request attributes -- on /authorize just the realm ChfOAuth2Request seeds from the RealmContext;
        // on the device flow the whole device-code record, which is the only source those keys have there (D2).
        Map<String, Object> data = new HashMap<>();
        for (String key : MODEL_KEYS) {
            Object value = o2.getAttribute(key);
            if (value != null) {
                data.put(key, value);
            }
        }

        // 2. Query overlay -- query wins. Read through getQueryParameter, never getParameter: the producer
        // copied getQuery().getValuesMap(), which is query-only, and 5b-2 renders this same model from a POST
        // whose form body getParameter would read (R-5b1.9). An absent parameter is omitted, not null-valued,
        // so the templates' <#if x??> guards behave as they do today.
        for (String key : MODEL_KEYS) {
            String value = o2.getQueryParameter(key);
            if (value != null) {
                data.put(key, value);
            }
        }

        // 3. Derived keys, strictly last.
        data.put("target", target(request));
        data.put("display_name", encodeForHTML(consentRequired.getClientName()));
        data.put("display_description", encodeForHTML(consentRequired.getClientDescription()));
        addDisplayScopesAndClaims(consentRequired, data);
        data.put("user_name", consentRequired.getUserDisplayName());
        data.put("xui", xuiState.isXUIEnabled());
        data.put("user_code", o2.getParameter(OAuth2Constants.DeviceCode.USER_CODE));
        data.put("baseUrl", baseURLProviderFactory.get(o2.<String>getParameter(OAuth2Constants.Custom.REALM))
                .getRootURL(o2.getHttpServletRequest()));
        data.put("saveConsentEnabled", consentRequired.isSaveConsentEnabled());
        data.put("csrf", csrfProtection.createCsrfToken(o2));
        data.put("locale", OAuth2Utils.joinStatic(o2.getAcceptedLanguages(), " "));

        return data;
    }

    /**
     * The form's post-back target: path plus query, from the <strong>CHF</strong> request URI rather than the
     * servlet request's. {@code ChfOAuth2Request.setQueryParameter} writes back through the same URI, exactly
     * as the Restlet accessors mutated the resource reference, so a servlet-request reconstruction would
     * silently drop query mutations (R-5b1.8). The path includes the context path, matching the live wire.
     */
    private static String target(Request request) {
        String path = request.getUri().getRawPath();
        String query = request.getUri().getRawQuery();
        return query == null || query.trim().isEmpty() ? path : path + "?" + query;
    }

    /**
     * Ported from {@code ConsentRequiredResource.addDisplayScopesAndClaims} verbatim in behaviour, including
     * the ordering quirk that the scope object is added to the array <em>before</em> {@code values} is put on
     * it -- which works because {@code JsonValue.getObject()} hands back the live underlying map, and which
     * the emitted JSON text depends on.
     */
    private void addDisplayScopesAndClaims(ResourceOwnerConsentRequired consentRequired,
            Map<String, Object> data) {
        JsonValue scopes = json(array());
        List<String> scopeNames = new ArrayList<>();
        Set<String> allScopeClaims = new HashSet<>();
        Map<String, List<String>> compositeScopes = consentRequired.getClaims().getCompositeScopes();
        Map<String, String> claimDescriptions = consentRequired.getClaimDescriptions();
        Map<String, Object> claimValues = new LinkedHashMap<>(consentRequired.getClaims().getValues());

        for (Map.Entry<String, String> scope : consentRequired.getScopeDescriptions().entrySet()) {
            if (scope.getValue() != null) {
                scopeNames.add(scope.getValue());
            }
            JsonValue value = json(object(field("name", encodeForHTML(scope.getValue()))));
            scopes.add(value.getObject());
            List<String> scopeClaims = compositeScopes.get(scope.getKey());
            if (scopeClaims != null) {
                LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
                value.put("values", claims);
                for (String claim : scopeClaims) {
                    Object claimValue = claimValues.get(claim);
                    if (claimValue != null) {
                        String claimDescription = claimDescriptions.get(claim);
                        if (claimDescription == null) {
                            claimDescription = claim;
                        }
                        claims.put(encodeForHTML(claimDescription), encodeForHTML(claimValue.toString()));
                        allScopeClaims.add(claim);
                    }
                }
            }
        }
        data.put("display_scopes", scopes.toString());
        // Raw (unencoded) descriptions for the WAP template, which escapes at the template layer. Written
        // after the query copy so a client cannot supply display_scope itself (CVE-2026-62280).
        data.put("display_scope", scopeNames);

        for (String claim : allScopeClaims) {
            claimValues.remove(claim);
        }

        JsonValue claims = json(array());
        for (Map.Entry<String, Object> claim : claimValues.entrySet()) {
            claims.add(object(
                    field("name", encodeForHTML(claimDescriptions.get(claim.getKey()))),
                    field("values", encodeForHTML(claim.getValue().toString()))));
        }
        data.put("display_claims", claims.toString());
    }

    private static String encodeForHTML(String description) {
        return ESAPI.encoder().encodeForHTML(description);
    }
}
