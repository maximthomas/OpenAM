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

import static org.forgerock.openam.audit.AuditConstants.Component;
import static org.forgerock.openam.audit.AuditConstants.TrackingIdKey.SESSION;
import static org.forgerock.openam.audit.AuditConstants.USER_ID;

import java.util.Set;

import org.forgerock.audit.AuditException;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.IntrospectableToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.Token;
import org.forgerock.openam.audit.AbstractHttpAccessAuditFilter;
import org.forgerock.openam.audit.AuditConstants;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openidconnect.OpenIdConnectToken;
import org.forgerock.services.context.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.shared.Constants;

/**
 * CHF replacement for {@code OAuth2AccessAuditFilter}/{@code OAuth2AbstractAccessAuditFilter}. Logs access audit
 * events for OAuth2 and OIDC requests under {@link Component#OAUTH}, deriving user id and tracking ids from the
 * request's tokens and SSO session. Constructed per-route with the endpoint's request/response body auditors — not
 * a Guice singleton, since the auditor pair varies per endpoint.
 */
public class OAuth2HttpAccessAuditFilter extends AbstractHttpAccessAuditFilter {

    private final OAuth2RequestFactory requestFactory;
    private final HttpBodyAuditor requestDetail;
    private final HttpBodyAuditor responseDetail;
    private final Logger logger = LoggerFactory.getLogger("oauth2");

    public OAuth2HttpAccessAuditFilter(AuditEventPublisher auditEventPublisher, AuditEventFactory auditEventFactory,
            OAuth2RequestFactory requestFactory, HttpBodyAuditor requestDetail, HttpBodyAuditor responseDetail) {
        super(Component.OAUTH, auditEventPublisher, auditEventFactory);
        this.requestFactory = requestFactory;
        this.requestDetail = requestDetail;
        this.responseDetail = responseDetail;
    }

    @Override
    protected String getUserIdForAccessAttempt(Context context, Request request) {
        String userId = super.getUserIdForAccessAttempt(context, request);
        if (StringUtils.isNotEmpty(userId)) {
            return userId;
        }
        putUserIdInAuditRequestContext(context, request);
        return super.getUserIdForAccessAttempt(context, request);
    }

    @Override
    protected Set<String> getTrackingIdsForAccessAttempt(Context context, Request request) {
        putTrackingIdsIntoAuditRequestContext(context, request);
        return super.getTrackingIdsForAccessAttempt(context, request);
    }

    @Override
    protected String getUserIdForAccessOutcome(Context context, Request request, Response response) {
        String userId = super.getUserIdForAccessOutcome(context, request, response);
        if (StringUtils.isNotEmpty(userId)) {
            return userId;
        }
        putUserIdInAuditRequestContext(context, request);
        return super.getUserIdForAccessOutcome(context, request, response);
    }

    @Override
    protected Set<String> getTrackingIdsForAccessOutcome(Context context, Request request, Response response) {
        putTrackingIdsIntoAuditRequestContext(context, request);
        return super.getTrackingIdsForAccessOutcome(context, request, response);
    }

    @Override
    protected JsonValue getRequestDetail(Context context, Request request) throws AuditException {
        return requestDetail == null ? null : requestDetail.apply(request.getEntity());
    }

    @Override
    protected JsonValue getResponseDetail(Context context, Request request, Response response) throws AuditException {
        return responseDetail == null ? null : responseDetail.apply(response.getEntity());
    }

    @Override
    protected String getRealm(Context context) {
        if (context.containsContext(RealmContext.class)) {
            return context.asContext(RealmContext.class).getRealm().asPath();
        }
        return null;
    }

    private void putUserIdInAuditRequestContext(Context context, Request request) {
        String userId = getUserId(context, request);
        if (userId != null) {
            AuditRequestContext.putProperty(USER_ID, userId);
        }
    }

    private void putTrackingIdsIntoAuditRequestContext(Context context, Request request) {
        OAuth2Request oAuth2Request = requestFactory.create(context, request);
        for (Token token : oAuth2Request.getTokens()) {
            AuditConstants.TrackingIdKey key = token.getAuditTrackingIdKey();
            String trackingId = token.getAuditTrackingId();
            if (key != null && trackingId != null) {
                AuditRequestContext.putProperty(key.toString(), trackingId);
            }
        }
        SSOToken ssoToken = getSSOToken(oAuth2Request);
        if (ssoToken != null) {
            try {
                AuditRequestContext.putProperty(SESSION.toString(), ssoToken.getProperty(Constants.AM_CTX_ID));
            } catch (SSOException e) {
                logger.debug("Could not get tracking ID for session", e);
            }
        } else {
            // No SSO token: fall back to the AM_CTX_ID request attribute (written by ClientAuthenticator).
            Object sessionTrackingId = oAuth2Request.getAttribute(Constants.AM_CTX_ID);
            if (sessionTrackingId != null) {
                AuditRequestContext.putProperty(SESSION.toString(), (String) sessionTrackingId);
            }
        }
    }

    private String getUserId(Context context, Request request) {
        OAuth2Request oAuth2Request = requestFactory.create(context, request);
        for (Token token : oAuth2Request.getTokens()) {
            if (token instanceof IntrospectableToken) {
                return ((IntrospectableToken) token).getResourceOwnerId();
            } else if (token instanceof OpenIdConnectToken) {
                return ((OpenIdConnectToken) token).get(OAuth2Constants.JWTTokenParams.SUB).asString();
            }
        }
        SSOToken ssoToken = getSSOToken(oAuth2Request);
        try {
            return ssoToken == null ? null : ssoToken.getProperty(Constants.UNIVERSAL_IDENTIFIER);
        } catch (SSOException e) {
            logger.debug("Could not get user ID for session", e);
            return null;
        }
    }

    /**
     * Resolves the SSO session for the request. Overridable so tests can supply a session without the
     * {@link SSOTokenManager} static.
     */
    protected SSOToken getSSOToken(OAuth2Request oAuth2Request) {
        try {
            return SSOTokenManager.getInstance().createSSOToken(oAuth2Request.getHttpServletRequest());
        } catch (Exception e) {
            logger.debug("Could not get session", e);
            return null;
        }
    }
}
