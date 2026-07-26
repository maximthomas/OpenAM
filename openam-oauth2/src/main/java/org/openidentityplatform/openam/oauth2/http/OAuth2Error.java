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

import static org.forgerock.oauth2.core.Utils.isEmpty;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.oauth2.core.exceptions.CsrfException;
import org.forgerock.oauth2.core.exceptions.DuplicateRequestParameterException;
import org.forgerock.oauth2.core.exceptions.InvalidClientAuthZHeaderException;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.OAuth2ProviderNotFoundException;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerAuthenticationRequired;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;

/**
 * Everything needed to render an OAuth2 error onto the wire: the RFC 6749 error fields, where they should
 * go, and any response header the error implies.
 * <p>
 * This is the transport-neutral replacement for {@code org.forgerock.oauth2.restlet.OAuth2RestletException},
 * and it is deliberately <strong>a value type rather than a {@code Throwable}</strong>. What handlers throw
 * stays the existing {@link OAuth2Exception} hierarchy, which the core already raises and which an
 * {@code @ExceptionHandler} method matches on directly; this class is what such a method <em>builds</em> on
 * its way to a {@code Response}, carrying the four things those exceptions do not know about -- the redirect
 * target, {@code state}, the parameter location and the authentication challenge.
 *
 * <h2>Why the redirect target is an explicit opt-in</h2>
 * The legacy exception decided "do not auto-redirect on an invalid {@code redirect_uri}" purely by which
 * constructor each catch block happened to pick -- the 4-argument form took {@code state} last and left the
 * redirect null, the 5-argument form took {@code redirectUri} in that position. Two constructors one
 * argument apart, with opposite security postures and no flag, no predicate and no marker to tell them
 * apart. {@code AuthorizeResource}'s GET and POST catch lists duly drifted, and POST ended up redirecting
 * {@code OAuth2ProviderNotFoundException} to a {@code redirect_uri} that -- there being no provider -- was
 * never validated.
 * <p>
 * Here redirecting is something a caller <em>does</em>, via {@link #redirectingTo}, and the policy of
 * whether it may is {@link #mayRedirect} -- data, not catch-clause ordering.
 */
public final class OAuth2Error {

    /**
     * Exception types that must never be redirected to a request-supplied {@code redirect_uri}, unified to
     * the union of what the GET and POST authorize paths each refused. Two rationales share this set and
     * must not be pruned together:
     * <ul>
     * <li><em>security</em> -- for the first five, the {@code redirect_uri} cannot have been validated by
     *     the time the error is raised, because the client, the provider or the URI itself is what failed.
     *     Redirecting to it is an open redirect;
     * <li><em>ownership</em> -- {@link ResourceOwnerAuthenticationRequired} already carries its own target,
     *     the login page. Nothing may retarget it; see {@link #of(OAuth2Exception)}.
     * </ul>
     * Matched by assignability, so {@code InvalidClientAuthZHeaderException} and
     * {@code OAuth2ProviderNotFoundException} resolve through their parents.
     */
    private static final List<Class<? extends OAuth2Exception>> NEVER_REDIRECT = List.of(
            RedirectUriMismatchException.class,
            InvalidClientException.class,
            OAuth2ProviderNotFoundException.class,
            DuplicateRequestParameterException.class,
            CsrfException.class,
            ResourceOwnerAuthenticationRequired.class);

    /** RFC 6749 section 5.2's code for an unexpected condition, which is what a missing code is. */
    private static final String SERVER_ERROR = "server_error";

    private final int statusCode;
    private final String error;
    private final String description;
    private String redirectUri;
    private String state;
    private UrlLocation parameterLocation;
    private String challengeScheme;
    private String challengeRealm;

    /**
     * Set when the redirect target came from the exception rather than from the request, which today means
     * only the login page. It makes {@link #redirectingTo} a no-op, so a generic mapper that opts every
     * error into redirecting cannot silently replace the login redirect with the client's URI, and it is
     * what {@code OAuth2ErrorResponseFactory} dispatches the login-redirect branch on.
     */
    private final boolean redirectUriPinned;

    /**
     * The exception this error was mapped from, kept for the log only.
     * <p>
     * Not part of the wire shape and never rendered. It exists because severity cannot be read off the
     * status: {@code ServerException(Throwable)} is the core's wrap-any-bug path and D2 gives it a
     * <strong>400</strong>, so without the original the one line that records an internal fault would be an
     * unactionable message at debug level.
     */
    private final Throwable cause;

    private OAuth2Error(int statusCode, String error, String description, UrlLocation parameterLocation) {
        this(statusCode, error, description, parameterLocation, null, null, false);
    }

    /**
     * The mapping constructor, taking the three things only {@link #of(OAuth2Exception)} can know.
     * <p>
     * These are set here rather than assigned afterwards so that {@link #redirectUriPinned} and
     * {@link #cause} can be {@code final}. The pin is the flag that stops the login redirect being
     * retargeted to a client-supplied URI, and a mutable field on a value passed between the mapper, the
     * handler and the renderer is one stray {@code this.} away from being cleared; {@code final} makes that
     * a compile error rather than a review question. The remaining fields stay assignable because the
     * withers vary them, and each of those varies its copy, never {@code this}.
     */
    private OAuth2Error(int statusCode, String error, String description, UrlLocation parameterLocation,
            Throwable cause, String pinnedRedirectUri, boolean redirectUriPinned) {
        this.statusCode = statusCode;
        // An error code is the one field RFC 6749 makes mandatory, and asMap() has to emit something for it.
        // A caller-supplied one can be absent -- UmaException and of(int, String, String) both take it
        // verbatim -- and a null would reach the wire as {"error":null}, as a valueless `error` token in the
        // callback query, and, because page/error.ftl wraps the whole of pageData in <#if error??>, as a
        // blank page. Defaulting is the same choice D9 makes for a missing realm: an error path that renders
        // something truthful beats one that renders nothing.
        this.error = isEmpty(error) ? SERVER_ERROR : error;
        this.description = description;
        this.parameterLocation = parameterLocation == null ? UrlLocation.QUERY : parameterLocation;
        this.cause = cause;
        this.redirectUri = pinnedRedirectUri;
        this.redirectUriPinned = redirectUriPinned;
    }

    /**
     * Copy constructor backing the withers. Copying whole then overwriting one field, rather than threading
     * ten arguments through a canonical constructor, is what keeps this class from re-growing the positional
     * trap it exists to remove -- four of those ten are same-typed {@code String}s, so a swapped pair would
     * compile.
     */
    private OAuth2Error(OAuth2Error other) {
        this.statusCode = other.statusCode;
        this.error = other.error;
        this.description = other.description;
        this.redirectUri = other.redirectUri;
        this.state = other.state;
        this.parameterLocation = other.parameterLocation;
        this.challengeScheme = other.challengeScheme;
        this.challengeRealm = other.challengeRealm;
        this.redirectUriPinned = other.redirectUriPinned;
        this.cause = other.cause;
    }

    /**
     * Maps a core OAuth2 exception onto the wire fields it implies.
     * <p>
     * Two subclasses carry information the request cannot supply, so a mapper reading only status, error and
     * message would lose it: {@link ResourceOwnerAuthenticationRequired} knows the login page to send the
     * user agent to, and {@link InvalidClientAuthZHeaderException} knows the challenge RFC 6749 section 5.2
     * requires on its 401.
     *
     * @param exception the exception to map, never {@code null}.
     * @return the corresponding error.
     * @throws IllegalArgumentException if {@code exception} is {@code null}. Stated rather than left to a
     *     bare {@code NullPointerException} because the sibling {@link #mayRedirect} <em>does</em> accept
     *     {@code null}, and a caller holding one exception reference passes it to both.
     */
    public static OAuth2Error of(OAuth2Exception exception) {
        if (exception == null) {
            throw new IllegalArgumentException("cannot build an OAuth2Error from a null exception");
        }
        boolean authenticationRequired = exception instanceof ResourceOwnerAuthenticationRequired;
        URI loginUri = authenticationRequired
                ? ((ResourceOwnerAuthenticationRequired) exception).getRedirectUri()
                : null;
        OAuth2Error mapped = new OAuth2Error(exception.getStatusCode(), exception.getError(),
                exception.getMessage(), exception.getParameterLocation(), exception,
                loginUri == null ? null : loginUri.toString(), authenticationRequired);
        if (exception instanceof InvalidClientAuthZHeaderException) {
            InvalidClientAuthZHeaderException challenge = (InvalidClientAuthZHeaderException) exception;
            mapped.challengeScheme = challenge.getChallengeScheme();
            mapped.challengeRealm = challenge.getChallengeRealm();
        }
        return mapped;
    }

    /**
     * Builds an error directly, for the paths that have no core exception to map -- notably the framework's
     * own CREST error bodies, which {@code OAuth2ErrorFilter} rewrites into this shape.
     *
     * @param statusCode the HTTP status code.
     * @param error the RFC 6749 error code; {@code null} or empty becomes {@code server_error}.
     * @param description the human-readable description, may be {@code null}.
     * @return the error, with parameters defaulting to the query string.
     */
    public static OAuth2Error of(int statusCode, String error, String description) {
        return new OAuth2Error(statusCode, error, description, UrlLocation.QUERY);
    }

    /**
     * As {@link #of(int, String, String)}, but keeping the throwable that prompted the error for the log.
     * <p>
     * For the paths that <em>build</em> a status rather than mapping an exception's own, yet still have a
     * throwable worth recording -- {@code onIllegalArgument} is the case it was added for. Without it, an
     * {@link IllegalArgumentException} raised anywhere under a browser endpoint is reported as one line naming
     * neither the frame that threw nor the fault, which is survivable while the cause is a client's
     * {@code ?display=bogus} and not while it is a mis-wired collaborator.
     * <p>
     * A fourth factory rather than a {@code withCause} wither because {@link #cause} is {@code final}: the
     * withers copy-then-assign, which only works for the fields deliberately left assignable.
     *
     * @param statusCode the HTTP status code.
     * @param error the RFC 6749 error code; {@code null} or empty becomes {@code server_error}.
     * @param description the human-readable description, may be {@code null}.
     * @param cause the throwable to record, may be {@code null}. Never rendered and never on the wire.
     * @return the error, with parameters defaulting to the query string.
     */
    public static OAuth2Error of(int statusCode, String error, String description, Throwable cause) {
        return new OAuth2Error(statusCode, error, description, UrlLocation.QUERY, cause, null, false);
    }

    /**
     * Decides whether an exception may be redirected to a request-supplied {@code redirect_uri}.
     *
     * @param exception the exception to judge.
     * @return {@code false} for the never-redirect set and for {@code null}, {@code true} otherwise.
     */
    public static boolean mayRedirect(OAuth2Exception exception) {
        if (exception == null) {
            return false;
        }
        return NEVER_REDIRECT.stream().noneMatch(type -> type.isInstance(exception));
    }

    /**
     * @param state the {@code state} echoed back to the client, may be {@code null}.
     * @return a copy carrying that state.
     */
    public OAuth2Error withState(String state) {
        OAuth2Error copy = new OAuth2Error(this);
        copy.state = state;
        return copy;
    }

    /**
     * Attaches the {@code WWW-Authenticate} challenge this error implies.
     * <p>
     * {@link #of(OAuth2Exception)} already populates the challenge for the one exception that carries one,
     * so production code should not need this. It stays because the challenge has to be expressible
     * <em>independently of which branch renders the error</em> -- that is the whole of D14's guarantee, and
     * no exception produces "a challenge on a redirecting error", so nothing else can construct the state
     * that guarantee is about.
     *
     * @param challengeScheme the scheme, e.g. {@code Basic}.
     * @param challengeRealm the protection realm.
     * @return a copy carrying the challenge.
     */
    public OAuth2Error withChallenge(String challengeScheme, String challengeRealm) {
        OAuth2Error copy = new OAuth2Error(this);
        copy.challengeScheme = challengeScheme;
        copy.challengeRealm = challengeRealm;
        return copy;
    }

    /**
     * Opts this error into being delivered as a redirect carrying {@link #asMap()} as parameters.
     * <p>
     * Callers are expected to have consulted {@link #mayRedirect} first. This is a no-op when the target was
     * set by the exception itself -- see {@link #redirectUriPinned}.
     *
     * @param redirectUri the target, may be {@code null} or empty for "no redirect".
     * @param location whether the parameters go in the query or the fragment; {@code null} means query.
     * @return a copy aimed at that target.
     */
    public OAuth2Error redirectingTo(String redirectUri, UrlLocation location) {
        if (redirectUriPinned) {
            return this;
        }
        OAuth2Error copy = new OAuth2Error(this);
        copy.redirectUri = redirectUri;
        copy.parameterLocation = location == null ? UrlLocation.QUERY : location;
        return copy;
    }

    /**
     * @return whether this error has somewhere to redirect to. This is a question about state; whether
     *     redirecting is <em>permitted</em> is {@link #mayRedirect}.
     */
    public boolean hasRedirectUri() {
        return !isEmpty(redirectUri);
    }

    /**
     * Whether the redirect target came from the exception rather than from the request.
     * <p>
     * The renderer needs this to tell the login redirect -- which is a bare, cacheable 301 to a target the
     * provider chose -- from a client redirect, which is a 302 carrying {@link #asMap()}. Dispatching on the
     * status code instead would look equivalent, because {@link ResourceOwnerAuthenticationRequired} is the
     * only 307 today, but it asks the wrong question: any other error given status 307 and a client
     * {@code redirect_uri} would then be emitted as a cacheable permanent redirect to that URI with the
     * error parameters silently dropped.
     *
     * @return {@code true} only for a target this error was constructed with, never one given to
     *     {@link #redirectingTo}.
     */
    public boolean isRedirectUriFromException() {
        return redirectUriPinned;
    }

    /**
     * The RFC 6749 error parameters, in a fixed order.
     * <p>
     * The legacy {@code asMap()} was a {@code HashMap}, so its field order was deterministic-but-arbitrary
     * -- a pure function of {@code String.hashCode} over that key set, never a designed contract. The order
     * here is canonical; no client parses error parameters positionally.
     * <p>
     * {@code error_uri} is <strong>not</strong> carried. RFC 6749 defines it, and the legacy shape reserved
     * a slot for it, but the only way to populate that slot was {@code OAuth2RestletException.setErrorUri},
     * which has no caller -- so no response has ever contained the field. Re-add it when something produces
     * one, rather than keeping a wither that only tests can reach.
     *
     * @return a fresh mutable map of {@code error}, and any of {@code error_description} and {@code state}
     *     that are set.
     */
    public Map<String, String> asMap() {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("error", error);
        if (!isEmpty(description)) {
            map.put("error_description", description);
        }
        if (!isEmpty(state)) {
            map.put("state", state);
        }
        return map;
    }

    /**
     * @return the HTTP status code.
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * @return the RFC 6749 error code; never {@code null}, never empty.
     */
    public String getError() {
        return error;
    }

    /**
     * @return the human-readable description, or {@code null}.
     */
    public String getDescription() {
        return description;
    }

    /**
     * @return the redirect target, or {@code null}.
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * @return the {@code state} echoed back to the client, or {@code null}.
     */
    public String getState() {
        return state;
    }

    /**
     * @return the exception this error was mapped from, or {@code null} when it was built directly. For the
     *     log only; it is never rendered.
     */
    public Throwable getCause() {
        return cause;
    }

    /**
     * @return whether the error parameters belong in the query or the fragment; never {@code null}.
     */
    public UrlLocation getParameterLocation() {
        return parameterLocation;
    }

    /**
     * @return the {@code WWW-Authenticate} scheme, or {@code null} when the error implies no challenge.
     */
    public String getChallengeScheme() {
        return challengeScheme;
    }

    /**
     * @return the {@code WWW-Authenticate} realm, or {@code null}.
     */
    public String getChallengeRealm() {
        return challengeRealm;
    }
}
