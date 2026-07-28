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
import static org.mockito.Mockito.mock;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.restlet.ExceptionHandler;
import org.forgerock.oauth2.restlet.OAuth2Representation;
import org.forgerock.oauth2.restlet.OAuth2RestletException;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.restlet.Context;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.ChallengeRequest;
import org.restlet.data.ChallengeScheme;
import org.restlet.data.Header;
import org.restlet.data.Method;
import org.restlet.engine.security.AuthenticatorUtils;
import org.restlet.util.Series;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * A/B's the new error layer against the live Restlet {@code ExceptionHandler}, in one JVM, while both legs
 * can still be driven.
 *
 * <h2>What this is for, and what it is not for</h2>
 * Scoped deliberately to claims that were <em>beliefs</em> rather than observations: the exact URL-encoding
 * of error parameters (plan.md risk #3, "the row most likely to fail"), the spelling of the
 * {@code WWW-Authenticate} challenge (D14), and the shape of the two redirect branches. Anything that could
 * be read straight off the source is asserted in the per-class unit suites instead.
 * <p>
 * <strong>This test dies at Phase 5d.</strong> It imports Restlet on purpose, and it is a development-time
 * instrument: once the Restlet leg is deleted there is no oracle to compare against, and a "parity" test
 * with one leg is just a restatement of current behaviour.
 *
 * <h2>Three rows where the answer was not what the plan assumed</h2>
 * <ul>
 * <li><strong>The encoding agrees.</strong> Restlet's {@code Reference}/{@code Form} and CHF's
 *     {@code Uris.urlEncodeQueryParameterNameOrValue} produce identical output for spaces, {@code &amp;},
 *     {@code =}, {@code +} and non-ASCII. Risk #3 is closed by observation rather than argument.
 * <li><strong>Restlet doubles a trailing separator</strong> -- {@code cb?} becomes
 *     {@code cb?&amp;error=...}. Reproduced rather than tidied.
 * <li><strong>{@code {rid}} does not survive Restlet at all.</strong> D11 called the {@code Template} pass
 *     a URI-injection vector; what it actually does to an unbound variable is <em>delete</em> it, so today's
 *     provider redirects to {@code /cb/} rather than {@code /cb/{rid}}. The new layer emits the target
 *     verbatim, and that divergence is asserted here rather than merely described.
 * </ul>
 */
public class RestletErrorParityTest {

    /**
     * The live handler. Only {@code OAuth2Representation} is exercised by the two redirect branches; the
     * other three collaborators are reached solely by the HTML and JSON branches, which are out of scope
     * here -- rendering parity belongs to {@code RestletRendererParityTest}, and the JSON body is
     * {@code OAuth2Error.asMap}'s contract.
     */
    private final ExceptionHandler handler = new ExceptionHandler(
            new OAuth2Representation(mock(OAuth2RequestFactory.class)),
            mock(BaseURLProviderFactory.class), mock(OAuth2RequestFactory.class),
            mock(JacksonRepresentationFactory.class));

    /** Drives the live handler. Its public entry point unwraps {@code getCause()}, hence the wrapper. */
    private Response restlet(OAuth2RestletException exception) {
        Response response = new Response(new Request(Method.GET,
                "https://openam.example/openam/oauth2/authorize"));
        handler.handle(new Exception(exception), new Context(), response.getRequest(), response);
        return response;
    }

    /** The same parameters {@code OAuth2RestletException.asMap()} would produce, in canonical order. */
    private static Map<String, String> params(String description, String state) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("error", "invalid_request");
        if (description != null) {
            params.put("error_description", description);
        }
        if (state != null) {
            params.put("state", state);
        }
        return params;
    }

    // ------------------------------------------------------- the 307 branch emits 301

    @Test
    public void authenticationRequiredIsA301ToTheUntouchedLoginUri() {
        String loginUri = "https://openam.example/openam/UI/Login?goto=abc";

        Response restlet = restlet(new OAuth2RestletException(307, "redirection_temporary",
                "The request requires a redirect.", loginUri, "xyz"));

        // MODE_CLIENT_PERMANENT turns the 307 into a 301 on the wire, and asMap() is never applied -- no
        // error parameters and no state on the one redirect a user agent is allowed to cache.
        assertThat(restlet.getStatus().getCode()).isEqualTo(301);
        assertThat(restlet.getLocationRef().toString()).isEqualTo(loginUri);
    }

    // ------------------------------------------------- composition and encoding, A/B

    @DataProvider(name = "composition")
    public Object[][] composition() {
        return new Object[][] {
            {"no query", "https://app.example/cb", QUERY, "nope", "xyz"},
            {"existing query", "https://app.example/cb?a=1&b=2", QUERY, "nope", "xyz"},
            {"existing fragment", "https://app.example/cb?a=1#section", QUERY, "nope", "xyz"},
            {"trailing ?", "https://app.example/cb?", QUERY, "nope", "xyz"},
            {"trailing &", "https://app.example/cb?a=1&", QUERY, "nope", "xyz"},
            {"error only", "https://app.example/cb", QUERY, null, null},
            {"fragment replaces", "https://app.example/cb#stale=1", FRAGMENT, "nope", "xyz"},
            {"fragment keeps query", "https://app.example/cb?a=1", FRAGMENT, "nope", "xyz"},
            // risk #3 -- these four are the reason this test exists
            {"space", "https://app.example/cb", QUERY, "nope", "a b"},
            {"separators", "https://app.example/cb", QUERY, "nope", "a&b=c+d"},
            {"non-ascii", "https://app.example/cb", QUERY, "не найдено", null},
            {"non-ascii in a fragment", "https://app.example/cb", FRAGMENT, "не найдено", "a b&c"},
        };
    }

    @Test(dataProvider = "composition")
    public void redirectIsA302ToTheSameComposedUri(String label, String redirectUri, UrlLocation location,
            String description, String state) {
        Response restlet = restlet(new OAuth2RestletException(400, "invalid_request", description,
                redirectUri, state, location));

        assertThat(restlet.getStatus().getCode()).as(label).isEqualTo(302);
        // Compared as prefix + parameter set: Restlet's asMap() is a HashMap, so its field order is
        // arbitrary and the new layer deliberately fixes it (D1). Everything else -- the untouched prefix,
        // the parameter names, and every encoded byte of every value -- must match.
        assertThat(decompose(restlet.getLocationRef().toString(), location))
                .as(label)
                .isEqualTo(decompose(RedirectUris.compose(redirectUri, params(description, state), location),
                        location));
    }

    /**
     * Splits a composed target into its untouched prefix, its trailing fragment and the encoded
     * {@code name=value} tokens, so the two legs can be compared without asserting Restlet's arbitrary
     * field order. Prefix and fragment are map entries rather than discarded values, so a leg that mangles
     * either still fails.
     */
    private static Map<String, String> decompose(String composed, UrlLocation location) {
        Map<String, String> parsed = new LinkedHashMap<>();
        String parameters = composed;
        if (location != FRAGMENT) {
            // Query parameters are appended before any fragment, so peel the fragment off first -- otherwise
            // it stays glued to whichever parameter each leg happened to emit last.
            int hash = composed.indexOf('#');
            parameters = hash < 0 ? composed : composed.substring(0, hash);
            parsed.put("<fragment>", hash < 0 ? "" : composed.substring(hash));
        }
        int cut = parameters.indexOf(location == FRAGMENT ? '#' : '?');
        if (cut < 0) {
            // A leg that appended nothing at all is a real failure, but it must surface as a mismatch in the
            // comparison rather than as a StringIndexOutOfBounds thrown from this helper.
            parsed.put("<prefix>", parameters);
            parsed.put("<no-parameters>", "true");
            return parsed;
        }
        parsed.put("<prefix>", parameters.substring(0, cut));
        for (String token : parameters.substring(cut + 1).split("&")) {
            if (!token.isEmpty()) {
                String[] nameValue = token.split("=", 2);
                parsed.put(nameValue[0], nameValue.length == 1 ? "" : nameValue[1]);
            }
        }
        return parsed;
    }

    /** The encoded bytes themselves, not merely their equivalence, so a change on either leg is visible. */
    @Test
    public void errorParametersAreUtf8PercentEncodedOnBothLegs() {
        String encodedDescription = "error_description=%D0%BD%D0%B5%20%D0%BD%D0%B0%D0%B9%D0%B4%D0%B5%D0%BD%D0%BE";
        String encodedState = "state=a%20b%26c%3Dd%2Be";

        Response restlet = restlet(new OAuth2RestletException(400, "invalid_request", "не найдено",
                "https://app.example/cb", "a b&c=d+e"));

        assertThat(restlet.getLocationRef().toString()).contains(encodedDescription, encodedState);
        assertThat(RedirectUris.compose("https://app.example/cb", params("не найдено", "a b&c=d+e"), QUERY))
                .contains(encodedDescription, encodedState);
    }

    /**
     * ⚠ The one character the legs encode differently, found while porting {@code /oauth2/connect/endSession}
     * (5b-2a) and confirmed here against the real Restlet: a {@code /} inside a parameter <em>value</em>.
     * Restlet percent-encodes it, CHF's {@code Form.toQueryString} leaves it bare.
     *
     * <p>Both are legal and parse identically -- RFC 3986 §3.4 puts {@code /} in the {@code query} production
     * -- so a client reading {@code state} gets the same string either way. Recorded rather than fixed:
     * {@link RedirectUris} is shared with {@code /authorize}'s error redirect, so "fixing" the encoder would
     * change bytes on an already-committed endpoint to buy nothing a client can observe. See
     * plan.md's expected-divergences table.
     *
     * <p>This row exists because the assertion above would have caught it years earlier had its fixture value
     * contained a slash; asserting the difference explicitly keeps it from being rediscovered as a bug.
     */
    @Test
    public void aSlashInsideAValueIsEncodedByRestletAndNotByChf() {
        Response restlet = restlet(new OAuth2RestletException(400, "invalid_request", "d",
                "https://app.example/cb", "a/b"));

        assertThat(restlet.getLocationRef().toString()).contains("state=a%2Fb");
        assertThat(RedirectUris.compose("https://app.example/cb", params("d", "a/b"), QUERY))
                .contains("state=a/b");
    }

    // ---------------------------------------------------------------- the D11 divergence

    /**
     * The one composition row where the legs deliberately disagree. Restlet builds a {@code Template} from
     * the target, so {@code {rid}} is read as a variable and, being unbound, substituted with nothing.
     */
    @Test
    public void templateBracesAreDeletedByRestletAndPreservedByTheNewComposer() {
        Response restlet = restlet(new OAuth2RestletException(400, "invalid_request", "nope",
                "https://app.example/cb/{rid}", null));

        assertThat(restlet.getLocationRef().toString()).startsWith("https://app.example/cb/?");
        assertThat(RedirectUris.compose("https://app.example/cb/{rid}", params("nope", null), QUERY))
                .startsWith("https://app.example/cb/{rid}?");
    }

    // ------------------------------------------------------------------ the D14 spelling

    /**
     * Finding 11 predicted {@code Basic realm="<realm>"} by reading {@code RestletConstants} and Restlet's
     * serialiser; this is the row that makes it a fact. The header only materialises inside a connector, so
     * {@code setChallengeRequests} on a unit {@code Response} leaves nothing to read -- hence
     * {@code AuthenticatorUtils.formatRequest}, which is what the connector itself calls.
     */
    @Test
    public void theBasicChallengeSerialisesAsSchemeSpaceRealmInQuotes() {
        ChallengeRequest challenge = new ChallengeRequest(ChallengeScheme.HTTP_BASIC, "/subrealm");
        Response response = new Response(new Request(Method.POST,
                "https://openam.example/openam/oauth2/access_token"));
        response.setChallengeRequests(Collections.singletonList(challenge));

        String formatted = AuthenticatorUtils.formatRequest(challenge, response, new Series<>(Header.class));

        assertThat(formatted).isEqualTo("Basic realm=\"/subrealm\"");
    }
}
