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

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation.FRAGMENT;
import static org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation.QUERY;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.testng.annotations.Test;

/**
 * Unit coverage for the shared redirect composer.
 * <p>
 * The encoding assertions here pin what CHF does, which is not necessarily what Restlet did -- that A/B is
 * {@code RestletErrorParityTest}'s job (plan.md risk #3). What this class fixes is the composition itself:
 * fragment replaces, query appends, and nothing else about the URI moves.
 */
public class RedirectUrisTest {

    private static final Map<String, String> ERROR = Collections.singletonMap("error", "invalid_request");

    private static Map<String, String> errorWith(String key, String value) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("error", "invalid_request");
        params.put(key, value);
        return params;
    }

    // ------------------------------------------------------------------ query: appends

    @Test
    public void queryIsAddedWhenTheUriHasNone() {
        assertThat(RedirectUris.compose("https://app.example/cb", ERROR, QUERY))
                .isEqualTo("https://app.example/cb?error=invalid_request");
    }

    @Test
    public void queryAppendsAndPreservesExistingParameters() {
        assertThat(RedirectUris.compose("https://app.example/cb?a=1&b=2", ERROR, QUERY))
                .isEqualTo("https://app.example/cb?a=1&b=2&error=invalid_request");
    }

    @Test
    public void queryIsInsertedBeforeAnExistingFragment() {
        assertThat(RedirectUris.compose("https://app.example/cb?a=1#section", ERROR, QUERY))
                .isEqualTo("https://app.example/cb?a=1&error=invalid_request#section");
    }

    /** A doubled separator is what Restlet emits; see {@code RestletErrorParityTest}. */
    @Test
    public void queryAppendsAfterATrailingSeparator() {
        assertThat(RedirectUris.compose("https://app.example/cb?", ERROR, QUERY))
                .isEqualTo("https://app.example/cb?&error=invalid_request");
        assertThat(RedirectUris.compose("https://app.example/cb?a=1&", ERROR, QUERY))
                .isEqualTo("https://app.example/cb?a=1&&error=invalid_request");
    }

    @Test
    public void aNullLocationMeansQuery() {
        assertThat(RedirectUris.compose("https://app.example/cb", ERROR, null))
                .isEqualTo("https://app.example/cb?error=invalid_request");
    }

    // --------------------------------------------------------------- fragment: replaces

    @Test
    public void fragmentIsAddedWhenTheUriHasNone() {
        assertThat(RedirectUris.compose("https://app.example/cb", ERROR, FRAGMENT))
                .isEqualTo("https://app.example/cb#error=invalid_request");
    }

    @Test
    public void fragmentReplacesAnExistingFragment() {
        assertThat(RedirectUris.compose("https://app.example/cb#stale=1", ERROR, FRAGMENT))
                .isEqualTo("https://app.example/cb#error=invalid_request");
    }

    @Test
    public void fragmentLeavesTheQueryStringIntact() {
        assertThat(RedirectUris.compose("https://app.example/cb?a=1", ERROR, FRAGMENT))
                .isEqualTo("https://app.example/cb?a=1#error=invalid_request");
    }

    // ------------------------------------------------------------------------ ordering

    @Test
    public void parameterOrderFollowsTheMap() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("error", "invalid_scope");
        params.put("error_description", "nope");
        params.put("state", "xyz");

        assertThat(RedirectUris.compose("https://app.example/cb", params, QUERY))
                .isEqualTo("https://app.example/cb?error=invalid_scope&error_description=nope&state=xyz");
    }

    // ------------------------------------------------------------------------ encoding

    @Test
    public void spacesArePercentEncodedNotPlusEncoded() {
        assertThat(RedirectUris.compose("https://app.example/cb", errorWith("state", "a b"), QUERY))
                .endsWith("&state=a%20b");
    }

    @Test
    public void parameterSeparatorsInAValueAreEncoded() {
        assertThat(RedirectUris.compose("https://app.example/cb", errorWith("state", "a&b=c+d"), QUERY))
                .endsWith("&state=a%26b%3Dc%2Bd");
    }

    @Test
    public void nonAsciiValuesAreEncodedAsUtf8() {
        assertThat(RedirectUris.compose("https://app.example/cb", errorWith("error_description", "не найдено"),
                QUERY)).endsWith("&error_description=%D0%BD%D0%B5%20%D0%BD%D0%B0%D0%B9%D0%B4%D0%B5%D0%BD%D0%BE");
    }

    @Test
    public void encodingIsIdenticalInAFragment() {
        assertThat(RedirectUris.compose("https://app.example/cb", errorWith("state", "a b&c"), FRAGMENT))
                .isEqualTo("https://app.example/cb#error=invalid_request&state=a%20b%26c");
    }

    // ---------------------------------------------------------------------- D11, edges

    /**
     * D11. Restlet ran the redirect target through a {@code Template}, so {@code {...}} in a
     * client-supplied {@code redirect_uri} was variable-substituted -- a URI-injection vector on a value
     * that the redirecting error paths never validated. The target is emitted verbatim here, which also
     * means this class must not parse the URI: {@code java.net.URI} rejects braces outright.
     */
    @Test
    public void templateBracesInTheTargetArePassedThroughVerbatim() {
        assertThat(RedirectUris.compose("https://app.example/cb/{rid}", ERROR, QUERY))
                .isEqualTo("https://app.example/cb/{rid}?error=invalid_request");
    }

    @Test
    public void emptyParametersLeaveTheUriUntouched() {
        assertThat(RedirectUris.compose("https://app.example/cb#f", Collections.emptyMap(), FRAGMENT))
                .isEqualTo("https://app.example/cb#f");
        assertThat(RedirectUris.compose("https://app.example/cb", Collections.emptyMap(), QUERY))
                .isEqualTo("https://app.example/cb");
    }
}
