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

import static org.forgerock.openam.audit.AMAuditEventBuilderUtils.getAllAvailableTrackingIds;
import static org.forgerock.openam.audit.AuditConstants.USER_ID;

import java.util.Set;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.services.context.Context;

/**
 * CHF replacement for {@code UMAAccessAuditFilter}. Logs UMA access audit events under {@code Component.OAUTH},
 * inheriting the OAuth2 attempt behaviour but not re-deriving identity on the outcome — a UMA response carries no
 * user or context id, so the outcome hooks return whatever is already in the {@link AuditRequestContext}.
 */
public class UMAHttpAccessAuditFilter extends OAuth2HttpAccessAuditFilter {

    public UMAHttpAccessAuditFilter(AuditEventPublisher auditEventPublisher, AuditEventFactory auditEventFactory,
            OAuth2RequestFactory requestFactory, HttpBodyAuditor requestDetail, HttpBodyAuditor responseDetail) {
        super(auditEventPublisher, auditEventFactory, requestFactory, requestDetail, responseDetail);
    }

    @Override
    protected String getUserIdForAccessOutcome(Context context, Request request, Response response) {
        String userId = AuditRequestContext.getProperty(USER_ID);
        return userId == null ? "" : userId;
    }

    @Override
    protected Set<String> getTrackingIdsForAccessOutcome(Context context, Request request, Response response) {
        return getAllAvailableTrackingIds();
    }
}
