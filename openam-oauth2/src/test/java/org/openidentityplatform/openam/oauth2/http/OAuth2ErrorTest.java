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
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.AccessDeniedException;
import org.forgerock.oauth2.core.exceptions.AuthorizationDeclinedException;
import org.forgerock.oauth2.core.exceptions.AuthorizationPendingException;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.oauth2.core.exceptions.ClientAuthenticationFailureFactory;
import org.forgerock.oauth2.core.exceptions.CsrfException;
import org.forgerock.oauth2.core.exceptions.DuplicateRequestParameterException;
import org.forgerock.oauth2.core.exceptions.ExpiredTokenException;
import org.forgerock.oauth2.core.exceptions.InsufficientScopeException;
import org.forgerock.oauth2.core.exceptions.InteractionRequiredException;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidCodeException;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.InvalidTokenException;
import org.forgerock.oauth2.core.exceptions.LoginRequiredException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.OAuth2ProviderNotFoundException;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.RelativeRedirectUriException;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerAuthenticationRequired;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequiredException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.forgerock.oauth2.core.exceptions.UnsupportedGrantTypeException;
import org.forgerock.oauth2.core.exceptions.UnsupportedResponseTypeException;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;
import org.forgerock.openidconnect.exceptions.InvalidClientMetadata;
import org.forgerock.openidconnect.exceptions.InvalidPostLogoutRedirectUri;
import org.forgerock.openidconnect.exceptions.InvalidRedirectUri;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.google.common.reflect.ClassPath;

/**
 * Unit coverage for the neutral error carrier that replaces {@code OAuth2RestletException}.
 * <p>
 * Two of these tests are guards rather than examples. {@link #mayRedirectVerdict} enumerates every
 * concrete {@code OAuth2Exception} in the module because the no-redirect policy it encodes is today
 * emergent from catch-clause ordering, and the two orderings disagree; and
 * {@link #everyConcreteSubclassHasAVerdict} makes adding a subclass without deciding a build failure
 * rather than a silent default to "redirectable".
 */
public class OAuth2ErrorTest {

    private static final URI LOGIN_URI = URI.create("https://openam.example/openam/UI/Login?goto=x");

    /**
     * The package trees the verdict table must cover in full, matched as prefixes so subpackages and nested
     * classes are in scope. A subclass outside these would escape the guard; the one that already does,
     * {@code UmaException}, is covered by {@code UmaExceptionRedirectVerdictTest} in openam-uma.
     * <p>
     * {@code org.openidentityplatform.} is here because it is where this migration puts every class it
     * writes -- including the ones in this very package. A guard that watched only the inherited
     * {@code org.forgerock.} trees would have been blind to exactly the code being added.
     */
    private static final List<String> EXCEPTION_PACKAGES = Arrays.asList(
            "org.forgerock.oauth2.", "org.forgerock.openidconnect.", "org.forgerock.openam.oauth2.",
            "org.forgerock.openam.uma.", "org.openidentityplatform.");

    /**
     * {@code InvalidClientException} and its {@code InvalidClientAuthZHeaderException} subclass both have
     * package-private constructors and are only reachable through this factory in production too.
     */
    private static final ClientAuthenticationFailureFactory FAILURES = new ClientAuthenticationFailureFactory() {
        @Override
        protected boolean hasAuthorizationHeader(OAuth2Request request) {
            return true;
        }

        @Override
        protected String getRealm(OAuth2Request request) {
            return "/subrealm";
        }
    };

    private static InvalidClientException invalidClient() {
        return FAILURES.getException("who are you");
    }

    private static InvalidClientException invalidClientAuthZHeader() {
        return FAILURES.getException(mock(OAuth2Request.class), "bad secret");
    }

    // ---------------------------------------------------------------- asMap

    @Test
    public void asMapEmitsTheCanonicalFieldOrder() {
        OAuth2Error error = OAuth2Error.of(400, "invalid_request", "missing response_type").withState("xyz");

        assertThat(error.asMap()).containsExactly(
                entry("error", "invalid_request"),
                entry("error_description", "missing response_type"),
                entry("state", "xyz"));
    }

    @Test
    public void asMapOmitsOptionalFieldsThatAreNullOrEmpty() {
        assertThat(OAuth2Error.of(400, "invalid_request", null).asMap())
                .containsExactly(entry("error", "invalid_request"));

        assertThat(OAuth2Error.of(400, "invalid_request", "").withState("").asMap())
                .containsExactly(entry("error", "invalid_request"));
    }

    /**
     * {@code error_uri} is RFC 6749 and the legacy map reserved a slot for it, but its only setter
     * ({@code OAuth2RestletException.setErrorUri}) has no caller, so no response has ever carried one.
     * Dropped rather than kept as an untestable shape.
     */
    @Test
    public void asMapCarriesNoErrorUri() {
        assertThat(OAuth2Error.of(400, "invalid_request", "d").withState("s").asMap())
                .doesNotContainKey("error_uri");
    }

    /**
     * The error code is the one field RFC 6749 makes mandatory and the only one {@code asMap()} emits
     * unconditionally, so it is the one that must never be absent. A null would reach the wire as
     * {@code {"error":null}}, as a valueless {@code error} token in the callback query, and -- because
     * {@code page/error.ftl} wraps the whole of {@code pageData} in {@code <#if error??>} -- as a blank
     * page. Both factories take the code verbatim from a caller, {@code UmaException} included.
     */
    @Test
    public void aMissingErrorCodeBecomesServerErrorRatherThanNull() {
        assertThat(OAuth2Error.of(400, null, "d").getError()).isEqualTo("server_error");
        assertThat(OAuth2Error.of(400, "", "d").asMap()).containsEntry("error", "server_error");
    }

    @Test
    public void asMapIsDetachedFromTheError() {
        OAuth2Error error = OAuth2Error.of(400, "invalid_request", "d");
        error.asMap().put("error", "tampered");

        assertThat(error.asMap()).containsEntry("error", "invalid_request");
    }

    // ------------------------------------------------------- of(OAuth2Exception)

    @DataProvider(name = "statusAndError")
    public Object[][] statusAndError() {
        return new Object[][] {
            // ServerException is 400, not 500 -- the contract path is reproduced verbatim (D2).
            {new ServerException("boom"), 400, "server_error", "boom"},
            {new NotFoundException("no realm"), 404, "not_found", "no realm"},
            {new InvalidTokenException(), 401, "invalid_token", "The access token provided is expired, revoked, "
                    + "malformed, or invalid for other reasons."},
            {new AuthorizationDeclinedException(), 403, "authorization_declined",
                    "The user has declined authorization"},
        };
    }

    @Test(dataProvider = "statusAndError")
    public void ofCopiesStatusErrorAndDescription(OAuth2Exception exception, int status, String error,
            String description) {
        OAuth2Error mapped = OAuth2Error.of(exception);

        assertThat(mapped.getStatusCode()).isEqualTo(status);
        assertThat(mapped.getError()).isEqualTo(error);
        assertThat(mapped.getDescription()).isEqualTo(description);
    }

    @Test
    public void ofCopiesTheParameterLocation() {
        OAuth2Exception fragment = new InvalidRequestException("bad", UrlLocation.FRAGMENT);

        assertThat(OAuth2Error.of(fragment).getParameterLocation()).isEqualTo(UrlLocation.FRAGMENT);
        assertThat(OAuth2Error.of(new InvalidRequestException("bad")).getParameterLocation())
                .isEqualTo(UrlLocation.QUERY);
    }

    @Test
    public void ofPopulatesNoRedirectUriOrChallengeForOrdinaryExceptions() {
        OAuth2Error mapped = OAuth2Error.of(new InvalidRequestException("bad"));

        assertThat(mapped.hasRedirectUri()).isFalse();
        assertThat(mapped.getRedirectUri()).isNull();
        assertThat(mapped.getChallengeScheme()).isNull();
        assertThat(mapped.getChallengeRealm()).isNull();
    }

    // ------------------------------------------------- D13: the login redirect

    @Test
    public void ofCarriesTheLoginUriFromResourceOwnerAuthenticationRequired() {
        OAuth2Error mapped = OAuth2Error.of(new ResourceOwnerAuthenticationRequired(LOGIN_URI));

        assertThat(mapped.getStatusCode()).isEqualTo(307);
        assertThat(mapped.hasRedirectUri()).isTrue();
        assertThat(mapped.getRedirectUri()).isEqualTo(LOGIN_URI.toString());
        assertThat(mapped.getParameterLocation()).isEqualTo(UrlLocation.QUERY);
    }

    /**
     * The adversarial case D13 exists for: a generic mapper that opts every error into redirecting would
     * overwrite the login page with the client's unvalidated {@code redirect_uri}, turning the one
     * unauthenticated entry point into an open redirect that still looks correct (301 + a Location).
     */
    @Test
    public void redirectingToCannotOverwriteTheLoginUri() {
        OAuth2Error mapped = OAuth2Error.of(new ResourceOwnerAuthenticationRequired(LOGIN_URI))
                .redirectingTo("https://evil.example/steal", UrlLocation.FRAGMENT);

        assertThat(mapped.getRedirectUri()).isEqualTo(LOGIN_URI.toString());
        assertThat(mapped.getParameterLocation()).isEqualTo(UrlLocation.QUERY);
    }

    // --------------------------------------------- D14: the WWW-Authenticate challenge

    @Test
    public void ofCarriesTheChallengeFromInvalidClientAuthZHeaderException() {
        OAuth2Error mapped = OAuth2Error.of(invalidClientAuthZHeader());

        assertThat(mapped.getStatusCode()).isEqualTo(401);
        assertThat(mapped.getChallengeScheme()).isEqualTo("Basic");
        assertThat(mapped.getChallengeRealm()).isEqualTo("/subrealm");
    }

    @Test
    public void plainInvalidClientExceptionCarriesNoChallenge() {
        OAuth2Error mapped = OAuth2Error.of(invalidClient());

        assertThat(mapped.getStatusCode()).isEqualTo(400);
        assertThat(mapped.getChallengeScheme()).isNull();
        assertThat(mapped.getChallengeRealm()).isNull();
    }

    // ------------------------------------------------------------- redirect state

    @Test
    public void redirectingToSetsTheTargetAndLocation() {
        OAuth2Error error = OAuth2Error.of(400, "invalid_scope", "no")
                .redirectingTo("https://app.example/cb", UrlLocation.FRAGMENT);

        assertThat(error.hasRedirectUri()).isTrue();
        assertThat(error.getRedirectUri()).isEqualTo("https://app.example/cb");
        assertThat(error.getParameterLocation()).isEqualTo(UrlLocation.FRAGMENT);
    }

    @Test
    public void hasRedirectUriIsFalseForNullAndEmpty() {
        assertThat(OAuth2Error.of(400, "e", "d").redirectingTo(null, UrlLocation.QUERY).hasRedirectUri()).isFalse();
        assertThat(OAuth2Error.of(400, "e", "d").redirectingTo("", UrlLocation.QUERY).hasRedirectUri()).isFalse();
    }

    @Test
    public void withersReturnNewInstancesAndLeaveTheOriginalAlone() {
        OAuth2Error original = OAuth2Error.of(400, "invalid_request", "d");

        assertThat(original.withState("s")).isNotSameAs(original);
        assertThat(original.getState()).isNull();
        assertThat(original.withChallenge("Basic", "/").getChallengeScheme()).isEqualTo("Basic");
        assertThat(original.getChallengeScheme()).isNull();
    }

    /**
     * The renderer picks the bare cacheable 301 on this, not on the status code, so that an error given
     * status 307 <em>and</em> a client {@code redirect_uri} cannot be emitted as a permanent redirect to
     * that URI. Both must survive a wither, or the distinction is lost the moment state is added.
     */
    @Test
    public void onlyAnExceptionSuppliedTargetIsMarkedAsSuch() {
        OAuth2Error login = OAuth2Error.of(new ResourceOwnerAuthenticationRequired(LOGIN_URI));
        assertThat(login.isRedirectUriFromException()).isTrue();
        assertThat(login.withState("xyz").isRedirectUriFromException()).isTrue();

        OAuth2Error clientTarget = OAuth2Error.of(307, "redirection_temporary", "d")
                .redirectingTo("https://app.example/cb", UrlLocation.QUERY);
        assertThat(clientTarget.isRedirectUriFromException()).isFalse();
        assertThat(OAuth2Error.of(400, "invalid_request", "d").isRedirectUriFromException()).isFalse();
    }

    /**
     * Kept for the log, never rendered. Severity cannot be read off the status -- {@code ServerException}
     * wrapping a real bug is a 400 (D2) -- so the original has to survive this far or there is nothing left
     * to write a stack from. {@code ServerException(Throwable)} chains its cause for the same reason.
     */
    @Test
    public void ofKeepsTheExceptionAsTheCause() {
        IllegalStateException bug = new IllegalStateException("boom");
        OAuth2Error mapped = OAuth2Error.of(new ServerException(bug));

        assertThat(mapped.getStatusCode()).isEqualTo(400);
        assertThat(mapped.getError()).isEqualTo("server_error");
        assertThat(mapped.getCause()).isInstanceOf(ServerException.class);
        assertThat(mapped.getCause().getCause()).isSameAs(bug);
        assertThat(mapped.withState("s").getCause()).isSameAs(mapped.getCause());
        // Built directly -- the filter's path -- there is no exception to keep.
        assertThat(OAuth2Error.of(400, "invalid_request", "d").getCause()).isNull();
    }

    // --------------------------------------------------------- mayRedirect policy

    /**
     * Every concrete {@code OAuth2Exception} in the module, with its verdict. Two distinct rationales share
     * the {@code false} column and must not be pruned together:
     * <ul>
     * <li><em>security</em> -- the {@code redirect_uri} cannot have been validated by the time this error is
     *     raised, so redirecting to it is an open redirect (the client, the provider or the URI itself is
     *     what failed);
     * <li><em>ownership</em> -- {@code ResourceOwnerAuthenticationRequired} already knows its target, the
     *     login page, so nothing may retarget it (D13).
     * </ul>
     */
    private static Map<OAuth2Exception, Boolean> verdicts() {
        Map<OAuth2Exception, Boolean> verdicts = new LinkedHashMap<>();
        verdicts.put(new AccessDeniedException("denied"), true);
        verdicts.put(new AuthorizationDeclinedException(), true);
        verdicts.put(new AuthorizationPendingException(), true);
        verdicts.put(new BadRequestException("bad"), true);
        verdicts.put(new CsrfException(), false);                              // security
        verdicts.put(new DuplicateRequestParameterException("dup"), false);    // security
        verdicts.put(new ExpiredTokenException(), true);
        verdicts.put(new InsufficientScopeException("read"), true);
        verdicts.put(new InteractionRequiredException(), true);
        verdicts.put(invalidClientAuthZHeader(), false);                       // security, by assignability
        verdicts.put(invalidClient(), false);                                  // security
        verdicts.put(new InvalidCodeException("code"), true);
        verdicts.put(new InvalidGrantException(), true);
        verdicts.put(new InvalidRequestException("req"), true);
        verdicts.put(new InvalidScopeException("scope"), true);
        verdicts.put(new InvalidTokenException(), true);
        verdicts.put(new LoginRequiredException(), true);
        verdicts.put(new NotFoundException("nf"), true);
        verdicts.put(new OAuth2ProviderNotFoundException("np"), false);        // security, by assignability
        verdicts.put(new RedirectUriMismatchException(), false);               // security
        verdicts.put(new RelativeRedirectUriException(), true);
        verdicts.put(new ResourceOwnerAuthenticationRequired(LOGIN_URI), false); // ownership -- D13
        verdicts.put(new ResourceOwnerConsentRequiredException(UrlLocation.QUERY), true);
        verdicts.put(new ServerException("boom"), true);
        verdicts.put(new UnauthorizedClientException(), true);
        verdicts.put(new UnsupportedGrantTypeException("gt"), true);
        verdicts.put(new UnsupportedResponseTypeException("rt"), true);
        verdicts.put(new InvalidClientMetadata(), true);
        verdicts.put(new InvalidPostLogoutRedirectUri(), true);
        verdicts.put(new InvalidRedirectUri(), true);
        return verdicts;
    }

    @DataProvider(name = "redirectVerdicts")
    public Object[][] redirectVerdicts() {
        return verdicts().entrySet().stream()
                .map(entry -> new Object[] {entry.getKey(), entry.getValue()})
                .toArray(Object[][]::new);
    }

    @Test(dataProvider = "redirectVerdicts")
    public void mayRedirectVerdict(OAuth2Exception exception, boolean expected) {
        assertThat(OAuth2Error.mayRedirect(exception))
                .as(exception.getClass().getSimpleName())
                .isEqualTo(expected);
    }

    /**
     * R-3c.6. Without this, a new subclass silently inherits "redirectable" and the verdict table above
     * quietly stops being the policy it claims to be. {@code UmaException} lives in openam-uma, which this
     * module cannot see; its verdict is asserted by {@code UmaExceptionRedirectVerdictTest} there.
     */
    @Test
    public void everyConcreteSubclassHasAVerdict() throws IOException {
        Set<Class<?>> covered = verdicts().keySet().stream()
                .map(Object::getClass)
                .collect(Collectors.toSet());

        // getAllClasses rather than getTopLevelClasses, so a subclass declared as a nested class is still
        // seen -- that would otherwise be invisible to this guard and would silently inherit the
        // redirectable default, the exact drift R-3c.6 exists to catch. The name filter runs *before*
        // load(): the unfiltered classpath here is the whole of openam-core, openam-rest, CREST and CHF,
        // and loading every class in it to find thirty costs seconds and the metaspace to hold them.
        ClassPath classPath = ClassPath.from(OAuth2ErrorTest.class.getClassLoader());
        Set<Class<?>> onClasspath = classPath.getAllClasses().stream()
                .filter(info -> EXCEPTION_PACKAGES.stream().anyMatch(info.getName()::startsWith))
                .map(OAuth2ErrorTest::loadQuietly)
                .filter(type -> type != null && OAuth2Exception.class.isAssignableFrom(type))
                .filter(type -> !Modifier.isAbstract(type.getModifiers()))
                .collect(Collectors.toSet());

        assertThat(onClasspath).containsExactlyInAnyOrderElementsOf(covered);
    }

    /**
     * A whole-classpath scan meets classes whose optional dependencies are absent from this module's test
     * scope; those cannot be {@code OAuth2Exception} subclasses, so skipping them costs no coverage.
     */
    private static Class<?> loadQuietly(ClassPath.ClassInfo info) {
        try {
            return info.load();
        } catch (Throwable notLoadable) {
            return null;
        }
    }
}
