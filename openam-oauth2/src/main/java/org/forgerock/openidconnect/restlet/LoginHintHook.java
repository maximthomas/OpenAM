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
 * Copyright 2014-2016 ForgeRock AS.
 * Portions copyright 2026 3A Systems LLC.
 */

package org.forgerock.openidconnect.restlet;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.restlet.AuthorizeRequestHook;
import org.forgerock.oauth2.restlet.TokenRequestHook;
import org.openidentityplatform.openam.oauth2.http.ChfAuthorizeRequestHook;
import org.openidentityplatform.openam.oauth2.http.ChfTokenRequestHook;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.CookieSetting;
import org.restlet.util.Series;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.forgerock.openam.oauth2.OAuth2Constants.Custom.*;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.*;

/**
 * Hooks into the authorize and token request to set/unset a cookie containing the login_hint OIDC parameter, which
 * may be used by the authentication chain.
 */
public class LoginHintHook implements AuthorizeRequestHook, TokenRequestHook, ChfTokenRequestHook,
        ChfAuthorizeRequestHook {

    private static final Logger LOGGER = LoggerFactory.getLogger("OAuth2Provider");

    /**
     * Adds the login_hint value to cookie.
     * @param o2request The current OAuth2 request.
     * @param request The restlet request.
     * @param response The restlet response.
     */
    @Override
    public void beforeAuthorizeHandling(OAuth2Request o2request, Request request, Response response) {
        String loginHint = o2request.getParameter(LOGIN_HINT);
        if (loginHint != null && !loginHint.equals(request.getCookies().getFirstValue(LOGIN_HINT_COOKIE))) {
            CookieSetting cookie = new CookieSetting(0, LOGIN_HINT_COOKIE, loginHint);
            cookie.setPath("/");
            // set HttpOnly flag
            cookie.setAccessRestricted(true);
            response.getCookieSettings().add(cookie);
        }

    }

    /**
     * Once we're returning an auth code we can remove the login hint cookie.
     * @param o2request The current OAuth2 request.
     * @param request The restlet request.
     * @param response The restlet response.
     */
    @Override
    public void afterAuthorizeSuccess(OAuth2Request o2request, Request request, Response response) {
        // If we're still in the original authorize request, stop setting the cookie in the response
        Series<CookieSetting> cookiesSetInThisResponse = response.getCookieSettings();
        CookieSetting loginHintCookieSetting = cookiesSetInThisResponse.getFirst(LOGIN_HINT_COOKIE);
        if (loginHintCookieSetting != null && loginHintCookieSetting.getMaxAge() != 0) {
            cookiesSetInThisResponse.removeFirst(LOGIN_HINT_COOKIE);
        }
        removeCookie(request, response);
    }

    /**
     * Authentication has completed - remove the cookie.
     * @param o2request The current OAuth2 request.
     * @param request The restlet request.
     * @param response The restlet response.
     */
    @Override
    public void afterTokenHandling(OAuth2Request o2request, Request request, Response response) {
        removeCookie(request, response);
    }

    /**
     * CHF path: authentication has completed - remove the cookie via the servlet response.
     * @param o2request The current OAuth2 request.
     */
    @Override
    public void afterTokenHandling(OAuth2Request o2request) {
        if (loginHintCookieValue(o2request.getHttpServletRequest()) != null) {
            removeCookie(o2request);
        }
    }

    /**
     * CHF path: add the login_hint value to a cookie for the authentication chain.
     * @param o2request The current OAuth2 request.
     */
    @Override
    public void beforeAuthorizeHandling(OAuth2Request o2request) {
        String loginHint = o2request.getParameter(LOGIN_HINT);
        if (setsCookie(loginHint, loginHintCookieValue(o2request.getHttpServletRequest()))) {
            Cookie cookie = new Cookie(LOGIN_HINT_COOKIE, loginHint);
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            o2request.getHttpServletResponse().addCookie(cookie);
        }
    }

    /**
     * CHF path: once we're returning an auth code we can remove the login hint cookie.
     * <p>
     * Unlike the Restlet path, this cannot retract the {@code Set-Cookie} {@link #beforeAuthorizeHandling}
     * added -- a servlet response has no cookie-removal API -- so the expiry is emitted whenever that set
     * happened, as well as when the request already carried the cookie. Both headers go on the wire and the
     * browser applies them in order, ending with no cookie. Guarding this on the incoming cookie alone (as
     * {@link #afterTokenHandling} does) would leave the cookie set after a first authorize.
     *
     * @param o2request The current OAuth2 request.
     */
    @Override
    public void afterAuthorizeSuccess(OAuth2Request o2request) {
        String existing = loginHintCookieValue(o2request.getHttpServletRequest());
        if (existing != null || setsCookie(o2request.getParameter(LOGIN_HINT), existing)) {
            removeCookie(o2request);
        }
    }

    /**
     * {@link #beforeAuthorizeHandling}'s condition, as a function of the two values it reads -- so the
     * after-hook can decide whether a {@code Set-Cookie} went out without the hook holding any state (Guice
     * builds a separate instance per Multibinder, and one instance serves every request either way).
     */
    private static boolean setsCookie(String loginHint, String existingCookieValue) {
        if (loginHint == null || loginHint.equals(existingCookieValue)) {
            return false;
        }
        if (!isValidCookieValue(loginHint)) {
            // Otherwise the skip is invisible: the user sees a login form that was not pre-filled and the
            // provider log says nothing at all. The value is not logged -- it is a claimed identity.
            LOGGER.debug("login_hint not written to {}: value is not an RFC 6265 cookie-octet string",
                    LOGIN_HINT_COOKIE);
            return false;
        }
        return true;
    }

    /**
     * Whether every character is an RFC 6265 {@code cookie-octet}: printable ASCII except space, {@code "},
     * {@code ,}, {@code ;} and {@code \}.
     * <p>
     * {@code login_hint} is client-supplied, and a servlet container that validates on write (Tomcat's
     * default {@code Rfc6265CookieProcessor}) throws {@code IllegalArgumentException} while generating the
     * header -- outside any handler's reach, so it surfaces as a 500 rather than an OAuth2 error. Restlet
     * wrote the {@code Set-Cookie} itself and never validated, emitting a malformed header instead. We emit
     * none: identical bytes for every value Restlet could legally send, and no container-dependent failure
     * for the rest.
     */
    private static boolean isValidCookieValue(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x21 || c > 0x7E || c == '"' || c == ',' || c == ';' || c == '\\') {
                return false;
            }
        }
        return true;
    }

    /** Match the set-cookie's path/HttpOnly so the browser actually clears it. */
    private void removeCookie(OAuth2Request o2request) {
        Cookie cookie = new Cookie(LOGIN_HINT_COOKIE, "");
        cookie.setMaxAge(0);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        o2request.getHttpServletResponse().addCookie(cookie);
    }

    /**
     * @return the cookie's value, {@code ""} if it is present with a null value (so that a non-null answer
     * always means "present", as the presence check this replaced did), or {@code null} if absent.
     */
    private String loginHintCookieValue(HttpServletRequest request) {
        Cookie[] cookies = request == null ? null : request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (LOGIN_HINT_COOKIE.equals(cookie.getName())) {
                    return cookie.getValue() == null ? "" : cookie.getValue();
                }
            }
        }
        return null;
    }

    private void removeCookie(Request request, Response response) {
        // Delete the login hint cookie if it exists
        if (request.getCookies().getFirst(LOGIN_HINT_COOKIE) != null) {
            CookieSetting cookie = new CookieSetting(0, LOGIN_HINT_COOKIE, "");
            cookie.setMaxAge(0);
            response.getCookieSettings().add(cookie);
        }
    }

}
