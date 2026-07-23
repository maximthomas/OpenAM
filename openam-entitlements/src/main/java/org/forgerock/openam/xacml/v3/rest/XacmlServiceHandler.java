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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2026 3A Systems LLC.
 */

package org.forgerock.openam.xacml.v3.rest;

import static org.forgerock.json.resource.ResourceException.INTERNAL_ERROR;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import jakarta.inject.Inject;
import jakarta.inject.Named;

import org.forgerock.http.header.AcceptLanguageHeader;
import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.ForbiddenException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.openam.forgerockrest.utils.RestLog;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.xacml.v3.ImportStep;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.annotations.VisibleForTesting;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.delegation.DelegationEvaluator;
import com.sun.identity.delegation.DelegationException;
import com.sun.identity.delegation.DelegationPermission;
import com.sun.identity.delegation.DelegationPermissionFactory;
import com.sun.identity.entitlement.EntitlementException;
import com.sun.identity.entitlement.opensso.SubjectUtils;
import com.sun.identity.entitlement.xacml3.XACMLExportImport;
import com.sun.identity.entitlement.xacml3.XACMLPrivilegeUtils;
import com.sun.identity.entitlement.xacml3.core.PolicySet;
import com.sun.identity.shared.debug.Debug;

/**
 * Provides XACML based services: export and import of the policies defined within a realm.
 */
public class XacmlServiceHandler {

    private static final String REST = "rest";
    private static final String VERSION = "1.0";

    public static final String QUERY_PARAM_STRING = "filter";

    private static final String FORGEROCK_AUTH_CONTEXT = "org.forgerock.authentication.context";
    private static final String ROOT_REALM = "/";
    private static final String COMPONENT = "org.forgerock.openam.xacml.v3.rest.XacmlService";
    private static final String CONTENT_TYPE_XACML3 = "application/xacml+xml; version=3.0";

    private final XACMLExportImport importExport;
    private final PrivilegedAction<SSOToken> admin;
    private final Debug debug;
    private final RestLog restLog;
    private final DelegationEvaluator evaluator;

    /**
     * Constructor with dependencies exposed for unit testing.
     *
     * @param importExport Non null utility functions.
     * @param adminTokenAction Non null admin action function.
     * @param debug The debug instance for logging.
     * @param restLog The REST audit logger.
     * @param evaluator The delegation permission evaluator.
     */
    @Inject
    public XacmlServiceHandler(XACMLExportImport importExport, PrivilegedAction<SSOToken> adminTokenAction,
            @Named("frRest") Debug debug, RestLog restLog, DelegationEvaluator evaluator) {
        this.importExport = importExport;
        this.admin = adminTokenAction;
        this.debug = debug;
        this.restLog = restLog;
        this.evaluator = evaluator;
    }

    private Subject getAdminToken() {
        return SubjectUtils.createSubject(AccessController.doPrivileged(admin));
    }

    /**
     * Export all Policies defined within the Realm used to access this end point.
     *
     * <p>The end point supports the query parameter "filter" which can be used multiple times to
     * define the Search Filters which will restrict the output to only those Privileges which
     * match the Search Filters.
     */
    @Get
    public Response exportXACML(@Contextual Context context, @Contextual Request request) {
        String realm = getRealm(context);
        Locale locale = getRequestLocale(request);
        List<String> filters = new Form().fromRequestQuery(request).get(QUERY_PARAM_STRING);
        if (filters == null) {
            filters = Collections.emptyList();
        }

        try {
            if (!checkPermission("READ", context, request, realm)) {
                return errorResponse(new ForbiddenException());
            }

            PolicySet policySet = importExport.exportXACML(realm, getAdminToken(), filters);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            XACMLPrivilegeUtils.writeXMLToStream(policySet, outputStream);

            Response response = new Response(Status.OK);
            response.getHeaders().put("Content-Type", CONTENT_TYPE_XACML3);
            response.getHeaders().put("Content-Disposition", "attachment; filename=" + getPolicyAttachmentFileName(realm));
            response.setEntity(outputStream.toByteArray());
            return response;
        } catch (EntitlementException e) {
            debug.warning("Reading Policies failed", e);
            return errorResponse(new InternalServerErrorException(e.getLocalizedMessage(locale)));
        }
    }

    /**
     * Expects to receive XACML formatted XML which will be read and imported.
     */
    @Post
    public Response importXACML(@Contextual Context context, @Contextual Request request) {
        String realm = getRealm(context);
        Locale locale = getRequestLocale(request);
        boolean dryRun = "true".equalsIgnoreCase(new Form().fromRequestQuery(request).getFirst("dryrun"));

        try {
            if (!checkPermission("MODIFY", context, request, realm)) {
                return errorResponse(new ForbiddenException());
            }

            InputStream entityStream = request.getEntity().getRawContentInputStream();
            List<ImportStep> steps = importExport.importXacml(realm, entityStream, getAdminToken(), dryRun);

            if (steps.isEmpty()) {
                return errorResponse(new BadRequestException("No policies found in XACML document"));
            }

            List<Map<String, String>> result = new ArrayList<>();
            for (ImportStep step : steps) {
                Map<String, String> stepResult = new HashMap<>();
                stepResult.put("status", String.valueOf(step.getDiffStatus().getCode()));
                stepResult.put("name", step.getName());
                stepResult.put("type", step.getType());
                result.add(stepResult);
            }

            Response response = new Response(Status.OK);
            response.getHeaders().put("Content-Type", "application/json");
            response.setEntity(result);
            return response;
        } catch (EntitlementException e) {
            debug.warning("Importing XACML to policies failed", e);
            return errorResponse(new BadRequestException(e.getLocalizedMessage(locale)));
        }
    }

    private Response errorResponse(org.forgerock.json.resource.ResourceException exception) {
        JsonValue json = exception.toJsonValue();
        if (exception.getMessage() != null) {
            json.put("message", exception.getMessage());
        }
        return new Response(Status.valueOf(exception.getCode())).setEntity(json.getObject());
    }

    private String getRealm(Context context) {
        return context.asContext(RealmContext.class).getRealm().asPath();
    }

    /**
     * Get the client's preferred locale, or the server default if not specified.
     */
    private Locale getRequestLocale(Request request) {
        try {
            AcceptLanguageHeader header = request.getHeaders().get(AcceptLanguageHeader.class);
            if (header != null) {
                Locale preferred = header.getLocales().getPreferredLocale();
                if (preferred != null) {
                    return preferred;
                }
            }
        } catch (MalformedHeaderException e) {
            debug.warning("Could not parse Accept-Language header", e);
        }
        return Locale.getDefault();
    }

    private String getUrlLastSegment(Request request) {
        List<String> pathElements = request.getUri().getPathElements();
        return pathElements.isEmpty() ? "" : pathElements.get(pathElements.size() - 1);
    }

    /**
     * Figure the name of the attachment file that will be created to contain the policies.  See OPENAM-4974.
     * File naming agreed with Andy H.
     *
     * @param realm The realm
     * @return A suitable file name, involving the realm in a meaningful way.
     */
    private String getPolicyAttachmentFileName(String realm) {
        String result;
        if (ROOT_REALM.equals(realm)) {
            result = "realm-policies";
        } else {
            result = realm.substring(1).replace('/', '-') + "-realm-policies";
        }
        return result + ".xml";
    }

    /**
     * Check if this user has permission to perform the given action (which will be "read" in the case of export
     * and "modify" in the case of import).
     *
     * @return true if the user has permission, false otherwise.
     */
    @VisibleForTesting
    boolean checkPermission(String action, Context context, Request request, String realm)
            throws EntitlementException {

        try {
            String urlLastSegment = getUrlLastSegment(request);

            @SuppressWarnings("unchecked")
            final Map<String, String> authContext = (Map<String, String>)
                    context.asContext(AttributesContext.class).getAttributes().get(FORGEROCK_AUTH_CONTEXT);
            final String tokenId = authContext.get("tokenId");
            final SSOToken token = SSOTokenManager.getInstance().createSSOToken(tokenId);

            return checkPermission(action, urlLastSegment, realm, token);

        } catch (SSOException e) {
            debug.warning("XacmlService permission evaluation failed", e);
            throw new EntitlementException(INTERNAL_ERROR, e);
        }
    }

    /**
     * This "lower level" version of checkPermission is really only here to make testing easier.
     *
     * @return true if the user has the "action" permission (action being "READ" or "MODIFY"), false otherwise.
     */
    private boolean checkPermission(String action, String urlLastSegment, String realm, SSOToken token)
            throws EntitlementException {

        boolean result;
        try {
            final Set<String> actions = new HashSet<String>(Arrays.asList(action));
            final DelegationPermissionFactory permissionFactory = new DelegationPermissionFactory();
            final DelegationPermission permissionRequest = permissionFactory.newInstance(realm, REST, VERSION,
                    urlLastSegment, action, actions, Collections.<String, String>emptyMap());

            result = checkPermission(permissionRequest, token, urlLastSegment);

        } catch (SSOException e) {
            debug.warning("XacmlService permission evaluation failed", e);
            throw new EntitlementException(INTERNAL_ERROR, e);
        } catch (DelegationException e) {
            debug.warning("XacmlService permission evaluation failed", e);
            throw new EntitlementException(INTERNAL_ERROR, e);
        }

        return result;
    }

    /**
     * This is the most atomic of the checkPermissions and finally gives us something we can test without having to
     * mock out most of the universe.
     *
     * @param permissionRequest the permission request, forged from the realm, URL segment, action and other things
     * @param token the user's SSO token
     * @param urlLastSegment the last segment of the URL
     * @return true if the user has the "action" permission (action being "READ" or "MODIFY"), false otherwise.
     */
    @VisibleForTesting
    boolean checkPermission(DelegationPermission permissionRequest, SSOToken token, String urlLastSegment)
                                                throws DelegationException, SSOException {

        boolean result = evaluator.isAllowed(token, permissionRequest, Collections.EMPTY_MAP);
        if (result) {
            restLog.auditAccessGranted(COMPONENT, urlLastSegment, COMPONENT, token);
        } else {
            restLog.auditAccessDenied(COMPONENT, urlLastSegment, COMPONENT, token);
        }
        return result;
    }
}
