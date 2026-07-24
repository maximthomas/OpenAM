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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Map;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.InvalidTokenException;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openidconnect.UserInfoService;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link UserInfoHandler} ({@code /userinfo}). Single {@code @Get @Post} method answers both verbs
 * (5a-2 D2). An {@code InvalidTokenException} carries no challenge scheme, so -- unlike introspect -- there is no
 * {@code WWW-Authenticate} (parity with Restlet). No cache headers.
 */
public class UserInfoHandlerTest {

    private OAuth2RequestFactory requestFactory;
    private UserInfoService userInfoService;
    private OAuth2Request o2;
    private UserInfoHandler handler;

    @BeforeMethod
    public void setup() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        userInfoService = mock(UserInfoService.class);
        o2 = mock(OAuth2Request.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new UserInfoHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "userInfoService", userInfoService);
    }

    @Test
    public void getDispatchesToGetUserInfo() throws Exception {
        Map<String, Object> claims = Map.of("sub", "user1", "name", "User One");
        when(userInfoService.getUserInfo(o2)).thenReturn(new JsonValue(claims));

        Response response = dispatch("GET");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).isEqualTo(claims);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();
        assertThat(response.getHeaders().getFirst("Pragma")).isNull();
    }

    @Test
    public void postDispatchesToSameGetUserInfoMethod() throws Exception {
        Map<String, Object> claims = Map.of("sub", "user1");
        when(userInfoService.getUserInfo(o2)).thenReturn(new JsonValue(claims));

        Response response = dispatch("POST");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).isEqualTo(claims);
    }

    /** invalid_token has no challenge scheme -> no WWW-Authenticate (parity with the Restlet resource). */
    @Test
    public void invalidTokenIs401WithNoChallengeAndNoCacheHeaders() throws Exception {
        when(userInfoService.getUserInfo(o2)).thenThrow(new InvalidTokenException());

        Response response = dispatch("GET");

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_token");
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).isNull();
        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();
        assertThat(response.getHeaders().getFirst("Pragma")).isNull();
    }

    // --- helpers ----------------------------------------------------------------------------------

    private Response dispatch(String method) throws Exception {
        Request request = new Request().setMethod(method);
        return Endpoints.from(handler).handle(new RootContext(), request).getOrThrowUninterruptibly();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    private static void inject(Object target, String name, Object value) throws Exception {
        for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException keepWalking) {
                // field is declared on a superclass
            }
        }
        throw new NoSuchFieldException(name);
    }
}
