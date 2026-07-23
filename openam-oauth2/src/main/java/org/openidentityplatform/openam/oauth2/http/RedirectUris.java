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

import java.util.Map;

import org.forgerock.http.protocol.Form;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;

/**
 * Composes an OAuth2 redirect target: a client's {@code redirect_uri} plus a set of parameters, placed in
 * either the query string or the fragment.
 * <p>
 * Two near-identical copies of this exist today -- {@code ExceptionHandler:122-131} for the error path and
 * {@code OAuth2Representation.toRepresentation:148-173} for the success path -- and Phase 5b's port of the
 * latter collapses onto this class.
 *
 * <h2>Why this does string surgery rather than parsing the URI</h2>
 * The target is emitted verbatim, and that is a decision rather than laziness. Restlet composed redirects
 * through a {@code Redirector}, which ran the target through a {@code Template} and so substituted
 * {@code {...}} sequences -- on a value that the redirecting error paths take straight from the request
 * without validating. Reproducing that would be reproducing a URI-injection vector.
 * <p>
 * Emitting it verbatim rules out {@code MutableUri}/{@code java.net.URI}, which reject braces (and much
 * else) outright, where Restlet's lenient {@code Reference} did not. Parsing would turn a URI this provider
 * happily redirects to today into an exception on the error path.
 */
public final class RedirectUris {

    private RedirectUris() {
    }

    /**
     * Places {@code params} on {@code redirectUri}.
     * <p>
     * A fragment <strong>replaces</strong> whatever fragment the target had; a query
     * <strong>appends</strong>, leaving existing query parameters and any fragment intact. Parameters are
     * emitted in the iteration order of {@code params}, so a {@code LinkedHashMap} gives a stable URL.
     * <p>
     * <strong>Empty {@code params} is a documented divergence, not an oversight.</strong> The target is
     * returned untouched, so a {@code FRAGMENT} call keeps any fragment the target already had rather than
     * clearing it -- where Restlet's {@code setFragment("")} would have replaced it. This row cannot be
     * A/B'd in {@code RestletErrorParityTest}: that test drives the real {@code ExceptionHandler}, and
     * {@code asMap()} always carries at least {@code error}, so an empty map is unreachable through it. The
     * case is likewise unreachable on the error path here; Phase 5b reusing this for the success path is
     * where an empty map first becomes plausible, and it should decide then whether clearing is wanted.
     *
     * @param redirectUri the target, which is not parsed, validated or normalised.
     * @param params the parameters to place; an empty map leaves the target untouched, fragment included.
     * @param location where to place them; {@code null} means the query string.
     * @return the composed target.
     */
    public static String compose(String redirectUri, Map<String, String> params, UrlLocation location) {
        Form form = new Form();
        params.forEach(form::add);
        String encoded = form.toQueryString();
        if (encoded.isEmpty()) {
            return redirectUri;
        }
        if (UrlLocation.FRAGMENT == location) {
            int hash = redirectUri.indexOf('#');
            return (hash < 0 ? redirectUri : redirectUri.substring(0, hash)) + "#" + encoded;
        }
        // Query parameters belong before the fragment, so split it off and re-attach it afterwards.
        int hash = redirectUri.indexOf('#');
        String beforeFragment = hash < 0 ? redirectUri : redirectUri.substring(0, hash);
        String fragment = hash < 0 ? "" : redirectUri.substring(hash);
        // A target already ending in a separator gets a second one -- "cb?" becomes "cb?&error=...". That is
        // what Restlet's Reference.addQueryParameters emits (observed, RestletErrorParityTest), it parses
        // identically, and suppressing it would be a divergence bought with extra code.
        String separator = beforeFragment.indexOf('?') < 0 ? "?" : "&";
        return beforeFragment + separator + encoded + fragment;
    }
}
