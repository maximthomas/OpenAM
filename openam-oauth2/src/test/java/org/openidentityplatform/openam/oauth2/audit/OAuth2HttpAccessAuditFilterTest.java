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
import static org.forgerock.openam.audit.AuditConstants.TrackingIdKey.SESSION;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.IntrospectableToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.Token;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openidconnect.OpenIdConnectToken;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.iplanet.sso.SSOToken;
import com.sun.identity.shared.Constants;

/**
 * Unit coverage for {@link OAuth2HttpAccessAuditFilter}'s identity/tracking derivation, exercised through the
 * protected hooks directly. The SSO-session seam is stubbed by overriding {@code getSSOToken}; the token seam by a
 * mocked {@link OAuth2RequestFactory}. This is the first coverage of this behaviour — the Restlet path shipped
 * untested — so the parity oracle remains the primary correctness instrument for the body auditors.
 */
public class OAuth2HttpAccessAuditFilterTest {

    private AuditEventPublisher publisher;
    private OAuth2RequestFactory requestFactory;
    private OAuth2Request oAuth2Request;
    private SSOToken ssoToken;   // stubbed session returned by getSSOToken; null unless a test sets it
    private RealmTestHelper realmTestHelper;
    private OAuth2HttpAccessAuditFilter filter;
    private Context context;
    private Request request;

    @BeforeMethod
    public void setUp() throws Exception {
        AuditRequestContext.clear();
        realmTestHelper = new RealmTestHelper();
        realmTestHelper.setupRealmClass();
        publisher = mock(AuditEventPublisher.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        oAuth2Request = mock(OAuth2Request.class);
        given(oAuth2Request.getTokens()).willReturn(emptyList());
        given(requestFactory.create(any(Context.class), any(Request.class))).willReturn(oAuth2Request);
        ssoToken = null;
        filter = new OAuth2HttpAccessAuditFilter(publisher, new AuditEventFactory(), requestFactory, null, null) {
            @Override
            protected SSOToken getSSOToken(OAuth2Request oAuth2Request) {
                return ssoToken;
            }
        };
        context = new RootContext();
        request = new Request();
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
        AuditRequestContext.clear();
    }

    @Test
    public void userIdFromIntrospectableToken() {
        IntrospectableToken token = mock(IntrospectableToken.class);
        given(token.getResourceOwnerId()).willReturn("resource-owner");
        given(oAuth2Request.getTokens()).willReturn(singletonList(token));

        assertThat(filter.getUserIdForAccessAttempt(context, request)).isEqualTo("resource-owner");
    }

    @Test
    public void userIdFromOpenIdConnectToken() {
        OpenIdConnectToken token = mock(OpenIdConnectToken.class);
        given(token.get("sub")).willReturn(new JsonValue("oidc-sub"));
        given(oAuth2Request.getTokens()).willReturn(singletonList(token));

        assertThat(filter.getUserIdForAccessAttempt(context, request)).isEqualTo("oidc-sub");
    }

    @Test
    public void userIdFromSsoSessionWhenNoTokens() throws Exception {
        ssoToken = mock(SSOToken.class);
        given(ssoToken.getProperty(Constants.UNIVERSAL_IDENTIFIER)).willReturn("id=demo,ou=user,dc=openam");

        assertThat(filter.getUserIdForAccessOutcome(context, request, new Response()))
                .isEqualTo("id=demo,ou=user,dc=openam");
    }

    @Test
    public void userIdEmptyWhenNoTokenAndNoSession() {
        assertThat(filter.getUserIdForAccessAttempt(context, request)).isEmpty();
    }

    @Test
    public void trackingIdsFromTokenKeyAndSsoSession() throws Exception {
        Token token = mock(Token.class);
        given(token.getAuditTrackingIdKey()).willReturn(OAUTH2_ACCESS);
        given(token.getAuditTrackingId()).willReturn("track-access");
        given(oAuth2Request.getTokens()).willReturn(singletonList(token));
        ssoToken = mock(SSOToken.class);
        given(ssoToken.getProperty(Constants.AM_CTX_ID)).willReturn("ctx-123");

        filter.getTrackingIdsForAccessAttempt(context, request);

        assertThat(AuditRequestContext.getProperty(OAUTH2_ACCESS.toString())).isEqualTo("track-access");
        assertThat(AuditRequestContext.getProperty(SESSION.toString())).isEqualTo("ctx-123");
    }

    @Test
    public void sessionTrackingIdFromRequestAttributeFallbackWhenNoSso() {
        // No SSO token: AM_CTX_ID is read from the OAuth2Request attribute map instead.
        given(oAuth2Request.getAttribute(Constants.AM_CTX_ID)).willReturn("attr-ctx");

        filter.getTrackingIdsForAccessAttempt(context, request);

        assertThat(AuditRequestContext.getProperty(SESSION.toString())).isEqualTo("attr-ctx");
    }

    @Test
    public void realmFromRealmContext() {
        Context realmContext = new RealmContext(new RootContext(), Realm.root());
        assertThat(filter.getRealm(realmContext)).isEqualTo(Realm.root().asPath());
    }

    @Test
    public void realmNullWithoutRealmContext() {
        assertThat(filter.getRealm(new RootContext())).isNull();
    }
}
