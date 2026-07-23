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
package org.openidentityplatform.openam.oauth2.audit;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.openam.audit.AuditConstants.TrackingIdKey.OAUTH2_ACCESS;
import static org.forgerock.openam.audit.AuditConstants.USER_ID;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.IntrospectableToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.Token;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.iplanet.sso.SSOToken;

/**
 * Unit coverage for {@link UMAHttpAccessAuditFilter}. It inherits the OAuth2 attempt behaviour (derive identity
 * from tokens) but overrides the outcome hooks so they do <em>not</em> re-derive — a UMA response carries no user
 * or context id. These tests pin exactly that difference.
 */
public class UMAHttpAccessAuditFilterTest {

    private AuditEventPublisher publisher;
    private OAuth2RequestFactory requestFactory;
    private OAuth2Request oAuth2Request;
    private UMAHttpAccessAuditFilter filter;
    private Context context;
    private Request request;

    @BeforeMethod
    public void setUp() {
        AuditRequestContext.clear();
        publisher = mock(AuditEventPublisher.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        oAuth2Request = mock(OAuth2Request.class);
        given(oAuth2Request.getTokens()).willReturn(emptyList());
        given(requestFactory.create(any(Context.class), any(Request.class))).willReturn(oAuth2Request);
        filter = new UMAHttpAccessAuditFilter(publisher, new AuditEventFactory(), requestFactory, null, null) {
            @Override
            protected SSOToken getSSOToken(OAuth2Request oAuth2Request) {
                return null; // no UMA test reaches the SSO fallback
            }
        };
        context = new RootContext();
        request = new Request();
    }

    @AfterMethod
    public void tearDown() {
        AuditRequestContext.clear();
    }

    @Test
    public void attemptStillDerivesUserIdFromToken() {
        IntrospectableToken token = mock(IntrospectableToken.class);
        given(token.getResourceOwnerId()).willReturn("resource-owner");
        given(oAuth2Request.getTokens()).willReturn(singletonList(token));

        assertThat(filter.getUserIdForAccessAttempt(context, request)).isEqualTo("resource-owner");
    }

    @Test
    public void outcomeDoesNotDeriveUserIdFromTokens() {
        IntrospectableToken token = mock(IntrospectableToken.class);
        given(token.getResourceOwnerId()).willReturn("resource-owner");
        given(oAuth2Request.getTokens()).willReturn(singletonList(token));

        assertThat(filter.getUserIdForAccessOutcome(context, request, new Response())).isEmpty();
    }

    @Test
    public void outcomeReturnsUserIdAlreadyInAuditContext() {
        AuditRequestContext.putProperty(USER_ID, "existing-user");

        assertThat(filter.getUserIdForAccessOutcome(context, request, new Response())).isEqualTo("existing-user");
    }

    @Test
    public void outcomeDoesNotSeedTrackingIdsFromTokens() {
        Token token = mock(Token.class);
        given(token.getAuditTrackingIdKey()).willReturn(OAUTH2_ACCESS);
        given(token.getAuditTrackingId()).willReturn("track-access");
        given(oAuth2Request.getTokens()).willReturn(singletonList(token));

        filter.getTrackingIdsForAccessOutcome(context, request, new Response());

        assertThat(AuditRequestContext.getProperty(OAUTH2_ACCESS.toString())).isNull();
    }
}
