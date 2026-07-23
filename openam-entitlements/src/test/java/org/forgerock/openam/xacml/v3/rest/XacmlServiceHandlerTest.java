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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.security.auth.Subject;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.forgerockrest.utils.RestLog;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.xacml.v3.DiffStatus;
import org.forgerock.openam.xacml.v3.ImportStep;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.mockito.ArgumentCaptor;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.delegation.DelegationEvaluator;
import com.sun.identity.delegation.DelegationPermission;
import com.sun.identity.entitlement.EntitlementException;
import com.sun.identity.entitlement.xacml3.XACMLExportImport;
import com.sun.identity.entitlement.xacml3.core.PolicySet;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.debug.Debug;

public class XacmlServiceHandlerTest {

    private AdminTokenAction adminTokenAction;
    private XACMLExportImport importExport;
    private Debug debug;
    private RestLog restLog;
    private DelegationEvaluator evaluator;
    private TestXacmlServiceHandler handler;
    private RealmTestHelper realmTestHelper;

    @BeforeMethod
    public void setup() throws Exception {
        importExport = mock(XACMLExportImport.class);
        debug = mock(Debug.class);
        restLog = mock(RestLog.class);
        evaluator = mock(DelegationEvaluator.class);
        adminTokenAction = mock(AdminTokenAction.class);
        doAnswer(ssoTokenAnswer()).when(adminTokenAction).run();
        handler = new TestXacmlServiceHandler(importExport, adminTokenAction, debug, restLog, evaluator);
        realmTestHelper = new RealmTestHelper();
        realmTestHelper.setupRealmClass();
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
    }

    private Answer<SSOToken> ssoTokenAnswer() {
        return new Answer<SSOToken>() {
            @Override
            public SSOToken answer(InvocationOnMock invocation) {
                SSOToken ssoToken = mock(SSOToken.class);
                try {
                    doReturn("my-uuid").when(ssoToken).getProperty(Constants.UNIVERSAL_IDENTIFIER);
                } catch (SSOException e) {
                    throw new RuntimeException(e);
                }
                return ssoToken;
            }
        };
    }

    private Context contextForRealm(String realm) throws Exception {
        String[] realmParts = realm.equals("/") ? new String[0] : realm.substring(1).split("/");
        return new RealmContext(new RootContext(), realmTestHelper.mockRealm(realmParts));
    }

    private Request requestFor(String method, String uri) throws Exception {
        return new Request().setMethod(method).setUri(uri);
    }

    @Test
    public void shouldImportXACML() throws Exception {
        List<ImportStep> steps = Arrays.asList(
                importStep(DiffStatus.ADD, "policy1", "privilege"),
                importStep(DiffStatus.UPDATE, "iPlanetAMWebAgentService", "application"));
        doReturn(steps).when(importExport).importXacml(eq("/"), any(), any(Subject.class), eq(false));

        Response response = handler.importXACML(contextForRealm("/"),
                requestFor("POST", "/xacml/policies").setEntity("<xacml/>".getBytes(StandardCharsets.UTF_8)));

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        @SuppressWarnings("unchecked")
        List<Map<String, String>> result = (List<Map<String, String>>) response.getEntity().getJson();
        assertThat(result.get(0)).contains(entry("status", "A"), entry("name", "policy1"), entry("type", "privilege"));
        assertThat(result.get(1)).contains(entry("status", "U"), entry("name", "iPlanetAMWebAgentService"),
                entry("type", "application"));
    }

    @Test
    public void shouldPassDryRunQueryParamThrough() throws Exception {
        doReturn(Collections.singletonList(importStep(DiffStatus.ADD, "policy1", "privilege")))
                .when(importExport).importXacml(eq("/"), any(), any(Subject.class), eq(true));

        Response response = handler.importXACML(contextForRealm("/"),
                requestFor("POST", "/xacml/policies?dryrun=true").setEntity(new byte[0]));

        assertThat(response.getStatus().getCode()).isEqualTo(200);
    }

    @Test
    public void shouldReturnBadRequestWhenImportHasNoPolicies() throws Exception {
        doReturn(Collections.emptyList()).when(importExport).importXacml(eq("/"), any(), any(), eq(false));

        Response response = handler.importXACML(contextForRealm("/"),
                requestFor("POST", "/xacml/policies").setEntity(new byte[0]));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(errorMessage(response)).startsWith("No policies found in XACML document");
    }

    @Test
    public void shouldReturnBadRequestWhenImportFails() throws Exception {
        doThrow(new EntitlementException(EntitlementException.JSON_PARSE_ERROR))
                .when(importExport).importXacml(eq("/"), any(), any(), eq(false));

        Response response = handler.importXACML(contextForRealm("/"),
                requestFor("POST", "/xacml/policies").setEntity(new byte[0]));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(errorMessage(response)).startsWith("JSON Exception.");
    }

    @Test
    public void shouldNotHtmlEscapeErrorMessage() throws Exception {
        // The error body must carry the raw message: XacmlXmlErrorFilter escapes it exactly once when it
        // renders XML, so pre-escaping here would double-escape (<policy> -> &amp;lt;policy&amp;gt;).
        EntitlementException failure = mock(EntitlementException.class);
        when(failure.getLocalizedMessage(any(Locale.class))).thenReturn("bad <policy> & \"stuff\"");
        doThrow(failure).when(importExport).importXacml(eq("/"), any(), any(), eq(false));

        Response response = handler.importXACML(contextForRealm("/"),
                requestFor("POST", "/xacml/policies").setEntity(new byte[0]));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(errorMessage(response)).isEqualTo("bad <policy> & \"stuff\"");
    }

    @Test
    public void shouldExportXACML() throws Exception {
        PolicySet policySet = new PolicySet();
        doReturn(policySet).when(importExport).exportXACML(eq("/"), any(Subject.class), any(List.class));

        Response response = handler.exportXACML(contextForRealm("/"), requestFor("GET",
                "/xacml/policies?filter=test1&filter=test2"));

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/xacml+xml; version=3.0");
        String xml = response.getEntity().getString();
        assertThat(xml).contains("<ns2:PolicySet");
        assertThat(xml).contains("xmlns:ns2=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\"");

        ArgumentCaptor<List> filtersCaptor = ArgumentCaptor.forClass(List.class);
        verify(importExport).exportXACML(eq("/"), any(Subject.class), filtersCaptor.capture());
        assertThat(filtersCaptor.getValue()).containsExactly("test1", "test2");
    }

    @Test
    public void shouldSetRootRealmDispositionFilename() throws Exception {
        assertDispositionFilename("/", "realm-policies.xml");
    }

    @Test
    public void shouldSetSubRealmDispositionFilename() throws Exception {
        assertDispositionFilename("/sub", "sub-realm-policies.xml");
    }

    @Test
    public void shouldSetSubSubRealmDispositionFilename() throws Exception {
        assertDispositionFilename("/sub1/sub2", "sub1-sub2-realm-policies.xml");
    }

    private void assertDispositionFilename(String realm, String expectedFilename) throws Exception {
        doReturn(new PolicySet()).when(importExport).exportXACML(eq(realm), any(Subject.class), any(List.class));

        Response response = handler.exportXACML(contextForRealm(realm), requestFor("GET", "/xacml/policies"));

        assertThat(response.getHeaders().getFirst("Content-Disposition"))
                .isEqualTo("attachment; filename=" + expectedFilename);
    }

    @Test
    public void shouldReturnInternalErrorWhenExportFails() throws Exception {
        doThrow(new EntitlementException(EntitlementException.JSON_PARSE_ERROR))
                .when(importExport).exportXACML(eq("/"), any(), any());

        Response response = handler.exportXACML(contextForRealm("/"), requestFor("GET", "/xacml/policies"));

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(errorMessage(response)).startsWith("JSON Exception.");
    }

    @Test
    public void shouldReturnForbiddenWhenPermissionDenied() throws Exception {
        handler.permissionGranted = false;

        Response response = handler.exportXACML(contextForRealm("/"), requestFor("GET", "/xacml/policies"));

        assertThat(response.getStatus().getCode()).isEqualTo(403);
    }

    @Test
    public void testPermissionsCheckSuccess() throws Exception {
        SSOToken adminToken = mock(SSOToken.class);
        DelegationPermission delegationPermission = mock(DelegationPermission.class);
        when(evaluator.isAllowed(adminToken, delegationPermission, Collections.EMPTY_MAP)).thenReturn(true);

        XacmlServiceHandler realHandler = new XacmlServiceHandler(importExport, adminTokenAction, debug, restLog,
                evaluator);
        boolean result = realHandler.checkPermission(delegationPermission, adminToken, "blah");

        assertThat(result).isTrue();
        verify(restLog).auditAccessGranted(anyString(), anyString(), anyString(), any(SSOToken.class));
    }

    @Test
    public void testPermissionsCheckFail() throws Exception {
        SSOToken adminToken = mock(SSOToken.class);
        DelegationPermission delegationPermission = mock(DelegationPermission.class);
        when(evaluator.isAllowed(adminToken, delegationPermission, Collections.EMPTY_MAP)).thenReturn(false);

        XacmlServiceHandler realHandler = new XacmlServiceHandler(importExport, adminTokenAction, debug, restLog,
                evaluator);
        boolean result = realHandler.checkPermission(delegationPermission, adminToken, "blah");

        assertThat(result).isFalse();
        verify(restLog).auditAccessDenied(anyString(), anyString(), anyString(), any(SSOToken.class));
    }

    private static ImportStep importStep(DiffStatus status, String name, String type) {
        ImportStep step = mock(ImportStep.class);
        doReturn(status).when(step).getDiffStatus();
        doReturn(name).when(step).getName();
        doReturn(type).when(step).getType();
        return step;
    }

    private static String errorMessage(Response response) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> error = (Map<String, Object>) response.getEntity().getJson();
        return String.valueOf(error.get("message"));
    }

    /**
     * Allows testing of XacmlServiceHandler's business logic without needing a real CAF auth
     * context / SSOToken / DelegationEvaluator wiring.
     */
    private static class TestXacmlServiceHandler extends XacmlServiceHandler {

        private boolean permissionGranted = true;

        TestXacmlServiceHandler(XACMLExportImport importExport, java.security.PrivilegedAction<SSOToken> admin,
                Debug debug, RestLog restLog, DelegationEvaluator evaluator) {
            super(importExport, admin, debug, restLog, evaluator);
        }

        @Override
        boolean checkPermission(String action, Context context, Request request, String realm) {
            return permissionGranted;
        }
    }
}
