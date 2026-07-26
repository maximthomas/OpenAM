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
package org.forgerock.openidconnect.restlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.openam.oauth2.OAuth2Constants.Custom.LOGIN_HINT_COOKIE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.forgerock.oauth2.core.OAuth2Request;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * CHF-path coverage for {@link LoginHintHook#afterTokenHandling(OAuth2Request)}: it clears the
 * {@code oidcLoginHint} cookie on the servlet response, mirroring the Restlet {@code removeCookie}. The
 * Restlet-path methods keep their own coverage; both impls live until 5d-2.
 */
public class LoginHintHookTest {

    @Test
    public void deletesLoginHintCookieWhenPresent() {
        OAuth2Request o2 = mock(OAuth2Request.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(LOGIN_HINT_COOKIE, "a-hint")});
        when(o2.getHttpServletRequest()).thenReturn(request);
        when(o2.getHttpServletResponse()).thenReturn(response);

        new LoginHintHook().afterTokenHandling(o2);

        ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
        verify(response).addCookie(captor.capture());
        Cookie deleted = captor.getValue();
        assertThat(deleted.getName()).isEqualTo(LOGIN_HINT_COOKIE);
        assertThat(deleted.getValue()).isEmpty();
        assertThat(deleted.getMaxAge()).isZero();
        assertThat(deleted.getPath()).isEqualTo("/");
        assertThat(deleted.isHttpOnly()).isTrue();
    }

    @Test
    public void doesNothingWhenCookieAbsent() {
        OAuth2Request o2 = mock(OAuth2Request.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getCookies()).thenReturn(null);   // no cookies on the request
        when(o2.getHttpServletRequest()).thenReturn(request);

        new LoginHintHook().afterTokenHandling(o2);

        verify(response, never()).addCookie(org.mockito.ArgumentMatchers.any());
    }

    // --- CHF authorize path (D4/D6) -------------------------------------------------------------

    @Test
    public void beforeAuthorizeSetsTheLoginHintCookie() {
        Fixture f = new Fixture("demo", null);

        new LoginHintHook().beforeAuthorizeHandling(f.o2);

        Cookie set = f.captureSingleCookie();
        assertThat(set.getName()).isEqualTo(LOGIN_HINT_COOKIE);
        assertThat(set.getValue()).isEqualTo("demo");
        assertThat(set.getPath()).isEqualTo("/");
        assertThat(set.isHttpOnly()).isTrue();
        assertThat(set.getMaxAge()).isNegative();   // session cookie, not a delete
    }

    @Test
    public void beforeAuthorizeDoesNothingWithoutALoginHint() {
        Fixture f = new Fixture(null, null);

        new LoginHintHook().beforeAuthorizeHandling(f.o2);

        verify(f.response, never()).addCookie(org.mockito.ArgumentMatchers.any());
    }

    /**
     * A {@code login_hint} the client controls must not be able to make the container throw. Tomcat's default
     * {@code Rfc6265CookieProcessor} rejects any value outside RFC 6265's cookie-octet when it generates the
     * header, and an {@code IllegalArgumentException} there is not an {@code OAuth2Exception}, so it would
     * bypass the browser mapper and reach the user agent as a CREST 500. Restlet wrote the header itself and
     * never validated, so the failure mode is new to the CHF port; skipping is the safe union.
     */
    @DataProvider(name = "unsafeHints")
    public Object[][] unsafeHints() {
        return new Object[][] {{"John Doe"}, {"a,b"}, {"a;b"}, {"a\\b"}, {"a\"b"}, {"Дёма"}};
    }

    @Test(dataProvider = "unsafeHints")
    public void beforeAuthorizeSkipsAHintThatIsNotAValidCookieValue(String hint) {
        Fixture f = new Fixture(hint, null);

        new LoginHintHook().beforeAuthorizeHandling(f.o2);

        verify(f.response, never()).addCookie(org.mockito.ArgumentMatchers.any());
    }

    /** ...and the after-hook agrees: nothing was set, nothing carried, so nothing to clear. */
    @Test
    public void afterAuthorizeSuccessEmitsNothingWhenTheHintWasSkipped() {
        Fixture f = new Fixture("John Doe", null);

        new LoginHintHook().afterAuthorizeSuccess(f.o2);

        verify(f.response, never()).addCookie(org.mockito.ArgumentMatchers.any());
    }

    /** The shapes a login_hint actually takes -- usernames and email addresses -- are all still written. */
    @Test
    public void beforeAuthorizeStillWritesOrdinaryHints() {
        Fixture f = new Fixture("demo.user+tag@example.com", null);

        new LoginHintHook().beforeAuthorizeHandling(f.o2);

        assertThat(f.captureSingleCookie().getValue()).isEqualTo("demo.user+tag@example.com");
    }

    /** Re-writing the same value would be noise; Restlet's before-hook skips it too. */
    @Test
    public void beforeAuthorizeDoesNothingWhenTheCookieAlreadyHoldsTheHint() {
        Fixture f = new Fixture("demo", "demo");

        new LoginHintHook().beforeAuthorizeHandling(f.o2);

        verify(f.response, never()).addCookie(org.mockito.ArgumentMatchers.any());
    }

    /**
     * D6, as corrected by the 5-E2 row 9b capture. A servlet response cannot retract the {@code Set-Cookie}
     * the before-hook added, so the delete must go out whenever that set happened -- otherwise the first
     * authorize carrying a {@code login_hint} would leave {@code oidcLoginHint} set in the browser, which is
     * an end-state divergence rather than merely an extra header. Restlet emitted nothing here.
     */
    @Test
    public void afterAuthorizeSuccessDeletesTheCookieItsBeforeHookSetEvenWithNoPriorCookie() {
        Fixture f = new Fixture("demo", null);

        LoginHintHook hook = new LoginHintHook();
        hook.beforeAuthorizeHandling(f.o2);
        hook.afterAuthorizeSuccess(f.o2);

        ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
        verify(f.response, org.mockito.Mockito.times(2)).addCookie(captor.capture());
        assertThat(captor.getAllValues().get(0).getValue()).isEqualTo("demo");
        Cookie deleted = captor.getAllValues().get(1);
        assertThat(deleted.getValue()).isEmpty();
        assertThat(deleted.getMaxAge()).isZero();
        assertThat(deleted.getPath()).isEqualTo("/");
        assertThat(deleted.isHttpOnly()).isTrue();
    }

    /** A cookie the request already carried is cleared even when this request sets nothing. */
    @Test
    public void afterAuthorizeSuccessDeletesAPriorCookie() {
        Fixture f = new Fixture("demo", "demo");

        new LoginHintHook().afterAuthorizeSuccess(f.o2);

        assertThat(f.captureSingleCookie().getMaxAge()).isZero();
    }

    /** Nothing set, nothing carried: no header at all, matching Restlet. */
    @Test
    public void afterAuthorizeSuccessEmitsNothingWhenThereIsNoCookieAndNoHint() {
        Fixture f = new Fixture(null, null);

        new LoginHintHook().afterAuthorizeSuccess(f.o2);

        verify(f.response, never()).addCookie(org.mockito.ArgumentMatchers.any());
    }

    /** A request whose {@code login_hint} and cookie disagree: the before-hook sets, so the after-hook clears. */
    @Test
    public void afterAuthorizeSuccessDeletesWhenTheHintDiffersFromThePriorCookie() {
        Fixture f = new Fixture("other", "demo");

        new LoginHintHook().afterAuthorizeSuccess(f.o2);

        assertThat(f.captureSingleCookie().getMaxAge()).isZero();
    }

    /** The servlet request/response pair a CHF hook sees, with the two inputs that decide every branch. */
    private static final class Fixture {

        final OAuth2Request o2 = mock(OAuth2Request.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);

        Fixture(String loginHintParameter, String existingCookieValue) {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getCookies()).thenReturn(existingCookieValue == null
                    ? null
                    : new Cookie[]{new Cookie(LOGIN_HINT_COOKIE, existingCookieValue)});
            when(o2.<String>getParameter("login_hint")).thenReturn(loginHintParameter);
            when(o2.getHttpServletRequest()).thenReturn(request);
            when(o2.getHttpServletResponse()).thenReturn(response);
        }

        Cookie captureSingleCookie() {
            ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
            verify(response).addCookie(captor.capture());
            return captor.getValue();
        }
    }
}
