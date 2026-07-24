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
}
