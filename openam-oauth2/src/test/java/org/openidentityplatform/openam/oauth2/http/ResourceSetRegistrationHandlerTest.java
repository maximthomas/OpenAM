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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.resources.ResourceSetStore;
import org.forgerock.oauth2.restlet.resources.ResourceSetDescriptionValidator;
import org.forgerock.oauth2.restlet.resources.ResourceSetRegistrationHook;
import org.forgerock.openam.oauth2.ResourceSetDescription;
import org.forgerock.openam.oauth2.extensions.ExtensionFilterManager;
import org.forgerock.openam.oauth2.extensions.ResourceRegistrationFilter;
import org.forgerock.openam.oauth2.resources.ResourceSetLabelRegistration;
import org.forgerock.openam.oauth2.resources.labels.LabelType;
import org.forgerock.openam.oauth2.resources.labels.ResourceSetLabel;
import org.forgerock.openam.oauth2.resources.labels.UmaLabelsStore;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.query.BaseQueryFilterVisitor;
import org.forgerock.util.query.QueryFilter;
import org.forgerock.util.query.QueryFilterVisitor;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link ResourceSetRegistrationHandler}, the CHF port of Restlet's
 * {@code ResourceSetRegistrationEndpoint}.
 * <p>
 * The conditional rows are the reason this class is long. Restlet evaluated {@code If-Match} /
 * {@code If-None-Match} in its own {@code ServerResource}, before the annotated method ran and on
 * <strong>every</strong> verb, so the port has to carry a precondition gate that no line of the Restlet
 * endpoint's source shows. Every conditional expectation here traces to a measured 5-E4 row (1, 1b, 2a, 2b, 3,
 * 3b, 9, 18, 19, 20, 21), never to RFC 7232 -- Restlet's rules and the RFC's disagree in four places and the
 * oracle dies at 5d-1.
 * <p>
 * ⚠ The fixture resource set is <strong>labelled</strong>, deliberately. The ETag is a hash of the
 * <em>read model</em>, whose {@code labels} come from {@code UmaLabelsStore} rather than from the store row,
 * and a port that hashes the bare {@code store.read} passes every unlabelled row while 412ing every real
 * client's conditional request (phase-5c finding 17).
 */
public class ResourceSetRegistrationHandlerTest {

    private static final String RSID = "rs-1";
    private static final String OWNER = "alice";
    private static final String CLIENT = "rs-client";
    private static final String REALM = "/";

    private OAuth2RequestFactory requestFactory;
    private OAuth2Request o2;
    private ResourceSetStore store;
    private UmaLabelsStore umaLabelsStore;
    private ResourceSetDescriptionValidator validator;
    private ResourceSetLabelRegistration labelRegistration;
    private ExtensionFilterManager extensionFilterManager;
    private ResourceSetRegistrationHook hook;
    private ResourceSetRegistrationHandler handler;

    @BeforeMethod
    public void setup() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        o2 = mock(OAuth2Request.class);
        store = mock(ResourceSetStore.class);
        umaLabelsStore = mock(UmaLabelsStore.class);
        validator = mock(ResourceSetDescriptionValidator.class);
        labelRegistration = mock(ResourceSetLabelRegistration.class);
        extensionFilterManager = mock(ExtensionFilterManager.class);
        hook = mock(ResourceSetRegistrationHook.class);

        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);
        when(o2.<String>getParameter("realm")).thenReturn(REALM);
        OAuth2ProviderSettings settings = mock(OAuth2ProviderSettings.class);
        when(settings.getResourceSetStore()).thenReturn(store);
        OAuth2ProviderSettingsFactory settingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        when(settingsFactory.get(any(OAuth2Request.class))).thenReturn(settings);
        when(extensionFilterManager.getFilters(any())).thenReturn(Collections.emptyList());
        // The validator is a pure function in production; echoing the input keeps the rows about the handler.
        when(validator.validate(any())).thenAnswer(invocation -> invocation.getArgument(0));

        handler = new ResourceSetRegistrationHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "providerSettingsFactory", settingsFactory);
        inject(handler, "validator", validator);
        inject(handler, "hooks", new LinkedHashSet<>(Collections.singletonList(hook)));
        inject(handler, "labelRegistration", labelRegistration);
        inject(handler, "extensionFilterManager", extensionFilterManager);
        inject(handler, "umaLabelsStore", umaLabelsStore);
    }

    private static void inject(Object target, String field, Object value) throws Exception {
        Field declared = findField(target.getClass(), field);
        declared.setAccessible(true);
        declared.set(target, value);
    }

    private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        try {
            return type.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            if (type.getSuperclass() == null) {
                throw e;
            }
            return findField(type.getSuperclass(), name);
        }
    }

    // ---------------------------------------------------------------- fixtures

    /** A stored resource set, exactly as {@code store.read} would hand it back: no {@code labels} key. */
    private static ResourceSetDescription stored() {
        Map<String, Object> description = new LinkedHashMap<>();
        description.put("name", "photo album");
        description.put("scopes", List.of("read", "write"));
        ResourceSetDescription resourceSet = new ResourceSetDescription(RSID, CLIENT, OWNER, description);
        resourceSet.setRealm(REALM);
        return resourceSet;
    }

    /** Puts the fixture behind {@code store.read} and gives it two labels in the label store. */
    private ResourceSetDescription readableWithLabels(String... labels) throws Exception {
        ResourceSetDescription resourceSet = stored();
        when(store.read(RSID, OWNER)).thenReturn(resourceSet);
        Set<ResourceSetLabel> labelSet = new LinkedHashSet<>();
        for (String label : labels) {
            labelSet.add(new ResourceSetLabel("id-" + label, label, LabelType.USER, Collections.emptySet()));
        }
        when(umaLabelsStore.forResourceSet(eq(REALM), eq(OWNER), eq(RSID), anyBoolean())).thenReturn(labelSet);
        return resourceSet;
    }

    /** The ETag the fixture's read model hashes to -- computed the way the handler must, not hard-coded. */
    private static String etagOf(ResourceSetDescription resourceSet, List<String> labels) {
        ResourceSetDescription model = new ResourceSetDescription(resourceSet.getId(), resourceSet.getClientId(),
                resourceSet.getResourceOwnerId(), new LinkedHashMap<>(resourceSet.getDescription().asMap()));
        model.setRealm(resourceSet.getRealm());
        model.setPolicyUri(resourceSet.getPolicyUri());
        model.getDescription().put("labels", labels);
        return "W/\"" + model.hashCode() + "\"";
    }

    private void onItem(String... conditionalHeaders) {
        when(o2.getAttribute("rsid")).thenReturn(RSID);
        stubToken();
    }

    private void onCollection() {
        when(o2.getAttribute("rsid")).thenReturn(null);
        stubToken();
    }

    private void stubToken() {
        when(o2.getToken(any())).thenAnswer(invocation -> {
            org.forgerock.oauth2.core.AccessToken token = mock(org.forgerock.oauth2.core.AccessToken.class);
            when(token.getClientId()).thenReturn(CLIENT);
            when(token.getResourceOwnerId()).thenReturn(OWNER);
            return token;
        });
    }

    private static Request request(String... headers) {
        Request request = new Request();
        for (int i = 0; i < headers.length; i += 2) {
            request.getHeaders().put(headers[i], headers[i + 1]);
        }
        return request;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    @SuppressWarnings("unchecked")
    private static Collection<String> idsOf(Response response) throws Exception {
        return (Collection<String>) response.getEntity().getJson();
    }

    /** A create/update body, as a resource server would send it. */
    private static Map<String, Object> created(String name, String... labels) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        body.put("scopes", List.of("read"));
        if (labels.length > 0) {
            body.put("labels", List.of(labels));
        }
        return body;
    }

    private static Request withBody(Request request, Map<String, Object> body) {
        return (Request) request.setEntity(body);
    }

    /** The legacy suite's fixture: every field {@link ResourceSetDescription}'s accessors read. */
    private static Map<String, Object> full(String name) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        body.put("uri", "URI");
        body.put("type", "TYPE");
        body.put("scopes", List.of("SCOPE"));
        body.put("icon_uri", "ICON_URI");
        return body;
    }

    /**
     * Flattens an AND-of-equals into field -> value. Reuses the legacy suite's visitor: everything
     * {@link BaseQueryFilterVisitor} does not override throws, so an {@code or}, a {@code not} or a
     * {@code startsWith} anywhere in the filter fails the row instead of being silently flattened away.
     */
    private static final QueryFilterVisitor<Map<String, String>, Map<String, String>, String> FIELDS =
            new BaseQueryFilterVisitor<Map<String, String>, Map<String, String>, String>() {
                @Override
                public Map<String, String> visitAndFilter(Map<String, String> fields,
                        List<QueryFilter<String>> subFilters) {
                    subFilters.forEach(subFilter -> subFilter.accept(this, fields));
                    return fields;
                }

                @Override
                public Map<String, String> visitEqualsFilter(Map<String, String> fields, String field, Object value) {
                    fields.put(field, String.valueOf(value));
                    return fields;
                }
            };

    /** The single filter {@code store.query} was called with, as field -> value. */
    @SuppressWarnings("unchecked")
    private Map<String, String> queriedFields() throws Exception {
        ArgumentCaptor<QueryFilter<String>> query = ArgumentCaptor.forClass(QueryFilter.class);
        verify(store).query(query.capture());
        return query.getValue().accept(FIELDS, new LinkedHashMap<>());
    }

    /** What {@code OpenAMResourceSetStore.create} does to the description it is handed. */
    private void assignedOnCreate(String id, String policyUri) throws Exception {
        org.mockito.Mockito.doAnswer(invocation -> {
            ResourceSetDescription resourceSet = invocation.getArgument(1);
            resourceSet.setId(id);
            resourceSet.setPolicyUri(policyUri);
            resourceSet.setRealm(REALM);
            return null;
        }).when(store).create(any(), any(ResourceSetDescription.class));
    }

    /**
     * Records what a {@code ResourceRegistrationFilter} sees on each side of {@code store.create}. Nothing
     * in-tree implements the SPI, so this is the only thing that can hold finding 18's ordering in place.
     */
    private static final class RecordingRegistrationFilter implements ResourceRegistrationFilter {

        private Set<String> beforeKeys;
        private String beforeId;
        private String beforePolicyUri;
        private Set<String> afterKeys;
        private String afterId;
        private String afterPolicyUri;

        @Override
        public void beforeResourceRegistration(ResourceSetDescription resourceSet) {
            beforeKeys = new LinkedHashSet<>(resourceSet.getDescription().keys());
            beforeId = resourceSet.getId();
            beforePolicyUri = resourceSet.getPolicyUri();
        }

        @Override
        public void afterResourceRegistration(ResourceSetDescription resourceSet) {
            afterKeys = new LinkedHashSet<>(resourceSet.getDescription().keys());
            afterId = resourceSet.getId();
            afterPolicyUri = resourceSet.getPolicyUri();
        }

        @Override
        public int compareTo(ResourceRegistrationFilter other) {
            return 0;
        }
    }

    // ---------------------------------------------------------------- GET: read and list

    @Test
    public void aReadAnswers200WithTheDescriptionTheIdAndTheEtag() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha", "beta");
        onItem();

        Response response = handler.readOrList(new RootContext(), request());

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        Map<String, Object> body = bodyOf(response);
        assertThat(body).containsEntry("_id", RSID).containsEntry("name", "photo album");
        // The labels the LABEL STORE holds, not the ones the caller sent -- finding 17's whole point.
        assertThat(body.get("labels")).isEqualTo(List.of("alpha", "beta"));
        assertThat(response.getHeaders().getFirst("ETag"))
                .isEqualTo(etagOf(resourceSet, List.of("alpha", "beta")));
        // 5-E4 row 14: bare, no charset. setEntity(Map) would have written "; charset=UTF-8".
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json");
    }

    @Test
    public void aListAnswersTheIdsAndNoEtag() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>(List.of(stored())));

        Response response = handler.readOrList(new RootContext(), request());

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(idsOf(response)).containsExactly(RSID);
        // 5-E4 row 5: the list carries no validator, which is what makes row 20's answers what they are.
        assertThat(response.getHeaders().getFirst("ETag")).isNull();
    }

    @Test
    public void theListQueryIsScopedToTheClientAndTheOwner() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>(List.of(stored())));

        handler.readOrList(new RootContext(), request());

        // ⚠ Both terms, ANDed. Losing resourceOwnerId lists every owner's resource sets to whoever holds a
        // PAT for the client; losing clientId leaks across resource servers. The other list rows stub
        // query(any()), so this is the only row that would notice either.
        assertThat(queriedFields()).containsOnly(entry("clientId", CLIENT), entry("resourceOwnerId", OWNER));
    }

    // ---------------------------------------------------------------- the shared precondition gate

    @Test
    public void aGetWithAMatchingIfNoneMatchIs304CarryingTheEtagAndNoBody() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();
        String etag = etagOf(resourceSet, List.of("alpha"));

        Response response = handler.readOrList(new RootContext(), request("If-None-Match", etag));

        // 5-E4 row 3: 304 carrying the ETag, with NO Content-Type at all.
        assertThat(response.getStatus().getCode()).isEqualTo(304);
        assertThat(response.getHeaders().getFirst("ETag")).isEqualTo(etag);
        assertThat(response.getHeaders().getFirst("Content-Type")).isNull();
        assertThat(response.getEntity().isRawContentEmpty()).isTrue();
    }

    @Test
    public void aGetWithTheStrongFormOfTheWeakTagIs200BecauseWeaknessIsComparedOnAGet() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();
        String strong = etagOf(resourceSet, List.of("alpha")).replace("W/", "");

        Response response = handler.readOrList(new RootContext(), request("If-None-Match", strong));

        assertThat(response.getStatus().getCode()).isEqualTo(200);      // 5-E4 row 21
    }

    @Test
    public void aGetWithAWildcardIfNoneMatchIs200AtTheItemUrl() throws Exception {
        readableWithLabels("alpha");
        onItem();

        Response response = handler.readOrList(new RootContext(), request("If-None-Match", "*"));

        assertThat(response.getStatus().getCode()).isEqualTo(200);      // 5-E4 row 3
    }

    @Test
    public void aGetWithAWildcardIfNoneMatchIs304AtTheCollectionUrl() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>(List.of(stored())));

        Response response = handler.readOrList(new RootContext(), request("If-None-Match", "*"));

        // ⚠ 5-E4 row 20: the OPPOSITE of the row above, because the list representation carries no tag and
        // Restlet's noneMatch wildcard is reachable only then.
        assertThat(response.getStatus().getCode()).isEqualTo(304);
        assertThat(response.getHeaders().getFirst("ETag")).isNull();
    }

    @Test
    public void aGetWithAStaleIfMatchIs412CarryingTheRepresentationAndTheEtag() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();

        Response response = handler.readOrList(new RootContext(), request("If-Match", "W/\"12345\""));

        // 5-E4 row 3b: a 200-shaped body under an error status, produced by no other path on this endpoint.
        // ResourceSetErrorFilter leaves it alone precisely because the entity is neither empty nor CREST.
        assertThat(response.getStatus().getCode()).isEqualTo(412);
        assertThat(bodyOf(response)).containsEntry("_id", RSID);
        assertThat(response.getHeaders().getFirst("ETag"))
                .isEqualTo(etagOf(resourceSet, List.of("alpha")));
    }

    @Test
    public void aGetWithAStaleIfMatchIs412CarryingTheIdArrayAtTheCollectionUrl() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>(List.of(stored())));

        Response response = handler.readOrList(new RootContext(), request("If-Match", "W/\"12345\""));

        assertThat(response.getStatus().getCode()).isEqualTo(412);      // 5-E4 row 20
        assertThat(idsOf(response)).containsExactly(RSID);
        assertThat(response.getHeaders().getFirst("ETag")).isNull();
    }

    @Test
    public void aGetWithAMatchingIfMatchIs200() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();

        Response response = handler.readOrList(new RootContext(),
                request("If-Match", etagOf(resourceSet, List.of("alpha"))));

        assertThat(response.getStatus().getCode()).isEqualTo(200);
    }

    // ---------------------------------------------------------------- POST: create

    @Test
    public void aCreateAnswers201WithTheIdThePolicyUriAndTheEtag() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>());
        assignedOnCreate("new-id", "https://as/policy/new-id");

        Response response = handler.create(new RootContext(), withBody(request(), created("photo album")));

        assertThat(response.getStatus().getCode()).isEqualTo(201);
        Map<String, Object> body = bodyOf(response);
        // createJsonResponse(desc, includeResourceSet = FALSE): the id and the policy uri, not the description.
        assertThat(body).containsOnlyKeys("_id", "user_access_policy_uri");
        assertThat(body).containsEntry("_id", "new-id");
        // 5-E4 row 5's exact form: weak, quoted, Integer.toString, negatives included.
        assertThat(response.getHeaders().getFirst("ETag")).matches("W/\"-?\\d+\"");
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json");
    }

    @Test
    public void aDuplicateNameIsAnInBand400CarryingAReasonPhraseAndTheOneCharset() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>(List.of(stored())));

        Response response = handler.create(new RootContext(), withBody(request(), created("photo album")));

        // ⚠ 5-E4 row 7. Built in band rather than thrown, which is why `error` holds a reason PHRASE where
        // every other error on this endpoint holds an OAuth2 error code -- and why it is the only response
        // that carries a charset. Both look like defects and both are the contract.
        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "Bad Request")
                .containsEntry("error_description", "A shared item with the name 'photo album' already exists");
        // ⚠ WITH a space, where 5-E4 row 7 measured `application/json;charset=UTF-8` without one. Asserted as
        // CHF actually emits it, deliberately: commons ContentTypeHeader.getValues() hard-codes "; charset=",
        // so a handler that stamps the bare bytes has them re-rendered. Phase-5-wide -- every ported HTML page
        // diverges the same way -- and recorded in plan.md's divergence table, not worked around here.
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        verify(store, never()).create(any(), any());
    }

    @Test
    public void theCreatedDescriptionCarriesTheValidatedBodyAndTheTokensClientAndOwner() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>());
        assignedOnCreate("new-id", null);
        // Not the echo stub: this is what tells the row whether the description is built from the VALIDATED
        // map or straight from the request body.
        Map<String, Object> validated = full("NAME");
        validated.put("type", "VALIDATED_TYPE");
        when(validator.validate(any())).thenReturn(validated);

        Map<String, Object> sent = full("NAME");
        sent.put("type", "RAW_TYPE");
        handler.create(new RootContext(), withBody(request(), sent));

        ArgumentCaptor<ResourceSetDescription> created = ArgumentCaptor.forClass(ResourceSetDescription.class);
        verify(store).create(any(), created.capture());
        // ⚠ The two ids are separate token fields and the same shape of string; swapping them leaves every
        // other row green and hands one resource server's shared items to another.
        assertThat(created.getValue().getClientId()).isEqualTo(CLIENT);
        assertThat(created.getValue().getResourceOwnerId()).isEqualTo(OWNER);
        assertThat(created.getValue().getName()).isEqualTo("NAME");
        assertThat(created.getValue().getUri()).isEqualTo(URI.create("URI"));
        assertThat(created.getValue().getType()).isEqualTo("VALIDATED_TYPE");
        assertThat(created.getValue().getScopes()).containsExactly("SCOPE");
        assertThat(created.getValue().getIconUri()).isEqualTo(URI.create("ICON_URI"));
        assertThat(created.getValue().getId()).isEqualTo("new-id");   // the store assigns it, not the handler
    }

    @Test
    public void theDuplicateCheckIsScopedToTheNameTheClientAndTheOwner() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>(List.of(stored())));
        RecordingRegistrationFilter filter = new RecordingRegistrationFilter();
        when(extensionFilterManager.getFilters(ResourceRegistrationFilter.class)).thenReturn(List.of(filter));

        handler.create(new RootContext(), withBody(request(), created("photo album")));

        // ⚠ All three terms, ANDed. Dropping clientId or resourceOwnerId makes one tenant's resource set
        // block another's -- and every other create row stubs query(any()), so nothing else notices.
        assertThat(queriedFields()).containsOnly(entry("name", "photo album"),
                entry("clientId", CLIENT), entry("resourceOwnerId", OWNER));
        // the duplicate path returns before the extension points, so the filter must see nothing at all
        assertThat(filter.beforeKeys).isNull();
        assertThat(filter.afterKeys).isNull();
    }

    @Test
    public void theExtensionPointSeesTheDescriptionWithoutLabelsAndWithoutAnIdThenWithBoth() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>());
        assignedOnCreate("new-id", "https://as/policy/new-id");
        RecordingRegistrationFilter filter = new RecordingRegistrationFilter();
        when(extensionFilterManager.getFilters(ResourceRegistrationFilter.class)).thenReturn(List.of(filter));

        handler.create(new RootContext(), withBody(request(), created("photo album", "alpha")));

        // finding 18's seven-step order, which nothing in-tree implements and no other test would catch.
        assertThat(filter.beforeKeys).doesNotContain("labels");
        assertThat(filter.beforeId).isNull();
        assertThat(filter.beforePolicyUri).isNull();
        assertThat(filter.afterKeys).contains("labels");
        assertThat(filter.afterId).isEqualTo("new-id");
        assertThat(filter.afterPolicyUri).isEqualTo("https://as/policy/new-id");
    }

    @Test
    public void labelsAreStrippedBeforeTheStoreAndComeBackAsAnEmptyListWhenAbsent() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>());
        assignedOnCreate("new-id", null);

        handler.create(new RootContext(), withBody(request(), created("photo album")));

        ArgumentCaptor<ResourceSetDescription> registered = ArgumentCaptor.forClass(ResourceSetDescription.class);
        verify(labelRegistration).updateLabelsForNewResourceSet(registered.capture());
        assertThat(registered.getValue().getDescription().get("labels").getObject()).isEqualTo(List.of());
    }

    @Test
    public void theCreateHookGetsTheRealm() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>());
        assignedOnCreate("new-id", null);

        handler.create(new RootContext(), withBody(request(), created("photo album")));

        // ⚠ The realm arrives as a request PARAMETER seeded from RealmContext. Mounted outside that filter the
        // hook silently gets null and OAuth2UrisFactory NPEs on every create (finding 16).
        verify(hook).resourceSetCreated(eq(REALM), any(ResourceSetDescription.class));
    }

    @Test
    public void aCreateIsConditionalToo() throws Exception {
        onCollection();

        Response response = handler.create(new RootContext(),
                withBody(request("If-Match", "W/\"12345\""), created("photo album")));

        // 5-E4 row 19: the collection has no tag, so only `*` can pass -- and this is a bare 412 whose body
        // ResourceSetErrorFilter supplies, unlike the GET's.
        assertThat(response.getStatus().getCode()).isEqualTo(412);
        assertThat(response.getEntity().isRawContentEmpty()).isTrue();
        verify(store, never()).create(any(), any());
    }

    @Test
    public void anUnconditionalPostAtAnItemUrlDoesNotReadThatResourceSet() throws Exception {
        onItem();
        when(store.query(any())).thenReturn(new LinkedHashSet<>());
        assignedOnCreate("new-id", null);

        Response response = handler.create(new RootContext(), withBody(request(), created("photo album")));

        // 5-E4 row 16: the rsid in the url is ignored and a NEW resource set is created. That only holds
        // because the gate is guarded by "was either header sent" -- computing a tag unconditionally would
        // read the addressed resource set and 404 when it does not exist.
        assertThat(response.getStatus().getCode()).isEqualTo(201);
        verify(store, never()).read(anyString(), anyString());
    }

    @Test
    public void anUnparseableBodyIs400BadRequestWithOrgJsonsOwnMessage() throws Exception {
        onCollection();
        Request request = request();
        request.setEntity("hello");

        assertThatThrownBy(() -> handler.create(new RootContext(), request))
                .isInstanceOf(BadRequestException.class)
                // ⚠ 5-E4 row 12 asserts this string exactly. It is org.json's, not Jackson's -- which is why
                // the handler parses with JSONObject first, exactly as Restlet's toMap did.
                .hasMessage("A JSONObject text must begin with '{' at 1 [character 2 line 1]");
    }

    @Test
    public void theBodyParserIsLenientTheWayOrgJsonIsLenient() throws Exception {
        // ⚠ 5-E4 row 22, measured through a raw client: single quotes, unquoted keys and trailing commas all
        // answer 201 on live Restlet, because the endpoint reaches `new JSONObject(<raw body>)` and org.json
        // accepts them. Parsing with Jackson instead -- the obvious simplification, one library instead of
        // two -- turns each of these into a 400 and switches off resource servers that work today.
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>());
        assignedOnCreate("new-id", null);

        for (String body : List.of("{'name':'photo album','scopes':['read']}",
                "{name:\"photo album\",scopes:[\"read\"]}",
                "{\"name\":\"photo album\",\"scopes\":[\"read\"],}")) {
            Request request = request();
            request.setEntity(body);
            assertThat(handler.create(new RootContext(), request).getStatus().getCode())
                    .describedAs(body).isEqualTo(201);
        }
    }

    @Test
    public void aDuplicateKeyIsRejectedWithOrgJsonsMessageWhereJacksonWouldTakeTheLastOne() throws Exception {
        // The other half of row 22, and the reason the parse cannot simply be Jackson-with-a-nicer-message:
        // Jackson accepts duplicate keys last-one-wins, so a Jackson port CREATES here.
        onCollection();
        Request request = request();
        request.setEntity("{\"name\":\"a\",\"name\":\"b\",\"scopes\":[\"read\"]}");

        assertThatThrownBy(() -> handler.create(new RootContext(), request))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Duplicate key \"name\" at 19 [character 20 line 1]");
    }

    @Test
    public void anAbsentBodyReachesTheValidatorAsAnEmptyDescriptionRatherThanFailingToParse() throws Exception {
        onCollection();
        when(validator.validate(Collections.emptyMap())).thenThrow(
                new BadRequestException("Invalid Resource Set Description. Missing required attribute, 'name'."));

        // Restlet's `entity == null` branch: no parse is attempted, and the VALIDATOR is what rejects it --
        // which is how an absent body and `{}` come out identical (5-E4 row 8).
        assertThatThrownBy(() -> handler.create(new RootContext(), request()))
                // ...and a checked OAuth2Exception passes through the runtime-exception guard untouched, so
                // it keeps its own 400 bad_request rather than becoming row 9's server_error.
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Invalid Resource Set Description. Missing required attribute, 'name'.");
    }

    // ---------------------------------------------------------------- PUT: update

    @Test
    public void anUpdateWithoutIfMatchIs400ServerErrorCarryingRestletsFormattedMessage() throws Exception {
        onItem();

        assertThatThrownBy(() -> handler.update(new RootContext(), withBody(request(), created("renamed"))))
                .isInstanceOf(ServerException.class)
                // ⚠ 5-E4 row 4: the `precondition_failed (512) - ` prefix is Restlet's ResourceException
                // formatting and reaches the wire verbatim. Throwing the bare sentence changes bytes on a
                // path the existing e2e already exercises.
                .hasMessage("precondition_failed (512) - Require If-Match header to update Resource Set");
        verify(store, never()).update(any());
    }

    @Test
    public void anUpdateWithAStaleIfMatchIsABare412() throws Exception {
        readableWithLabels("alpha");
        onItem();

        Response response = handler.update(new RootContext(),
                withBody(request("If-Match", "W/\"12345\""), created("renamed")));

        // 5-E4 row 1: 412, `{"error":"precondition_failed"}` from the filter, and NO ETag.
        assertThat(response.getStatus().getCode()).isEqualTo(412);
        assertThat(response.getEntity().isRawContentEmpty()).isTrue();
        assertThat(response.getHeaders().getFirst("ETag")).isNull();
        verify(store, never()).update(any());
    }

    @Test
    public void anUpdateWithAMatchingIfMatchAnswers200AndTheNewTag() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();
        String etag = etagOf(resourceSet, List.of("alpha"));

        Response response = handler.update(new RootContext(),
                withBody(request("If-Match", etag), created("renamed")));

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        verify(store).update(any(ResourceSetDescription.class));
        verify(labelRegistration).updateLabelsForExistingResourceSet(any(ResourceSetDescription.class));
        // 5-E4 row 2a: the PUT answers a tag on the same response, and it is the UPDATED description's --
        // so a handler that echoed the tag it just matched, or hashed the pre-update model, is caught here.
        assertThat(response.getHeaders().getFirst("ETag")).matches("W/\"-?\\d+\"").isNotEqualTo(etag);
        assertThat(bodyOf(response)).containsOnlyKeys("_id");
    }

    @Test
    public void theUpdatedDescriptionReplacesTheStoredOneAndKeepsTheIdTheClientAndTheOwner() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();
        Map<String, Object> body = full("NEW_NAME");
        body.remove("scopes");                  // the STORED fixture has scopes; this update does not resend them
        Set<String> keysTheStoreSaw = new LinkedHashSet<>();
        org.mockito.Mockito.doAnswer(invocation -> {
            // snapshotted at the call: the handler re-adds `labels` to the same object straight afterwards
            keysTheStoreSaw.addAll(((ResourceSetDescription) invocation.getArgument(0)).getDescription().keys());
            return null;
        }).when(store).update(any());

        handler.update(new RootContext(),
                withBody(request("If-Match", etagOf(resourceSet, List.of("alpha"))), body));

        ArgumentCaptor<ResourceSetDescription> updated = ArgumentCaptor.forClass(ResourceSetDescription.class);
        verify(store).update(updated.capture());
        // the identity is the stored row's, never the request's
        assertThat(updated.getValue().getId()).isEqualTo(RSID);
        assertThat(updated.getValue().getClientId()).isEqualTo(CLIENT);
        assertThat(updated.getValue().getResourceOwnerId()).isEqualTo(OWNER);
        assertThat(updated.getValue().getName()).isEqualTo("NEW_NAME");
        assertThat(updated.getValue().getUri()).isEqualTo(URI.create("URI"));
        assertThat(updated.getValue().getType()).isEqualTo("TYPE");
        assertThat(updated.getValue().getIconUri()).isEqualTo(URI.create("ICON_URI"));
        // ⚠ update() REPLACES the description, so a PUT that omits a field deletes it -- the same rule that
        // makes an update without `labels` clear the labels (5-E4 row 2a), here on an ordinary field.
        // Unordered: org.json's JSONObject is HashMap-backed, so the body's key order does not survive.
        assertThat(keysTheStoreSaw).containsExactlyInAnyOrder("name", "uri", "type", "icon_uri");
    }

    @Test
    public void anUpdateWithAMatchingIfNoneMatchIs412RatherThanTheUpdate() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();
        String etag = etagOf(resourceSet, List.of("alpha"));

        Response response = handler.update(new RootContext(),
                withBody(request("If-None-Match", etag), created("renamed")));

        // 5-E4 row 18: a match on a write verb is a 412, never a 304 -- and D6 gave If-None-Match to the GET
        // path alone, so a plan-faithful port performs the update here.
        assertThat(response.getStatus().getCode()).isEqualTo(412);
        verify(store, never()).update(any());
    }

    @Test
    public void anUpdateWithANonMatchingIfNoneMatchFallsThroughToTheMissingIfMatchRejection() throws Exception {
        readableWithLabels("alpha");
        onItem();

        assertThatThrownBy(() -> handler.update(new RootContext(),
                withBody(request("If-None-Match", "W/\"12345\""), created("renamed"))))
                .isInstanceOf(ServerException.class)
                // 5-E4 row 18: If-None-Match can refuse a write but never authorise one.
                .hasMessage("precondition_failed (512) - Require If-Match header to update Resource Set");
    }

    @Test
    public void anUpdateWithTheStrongFormInIfNoneMatchIs412BecauseAWriteComparesNamesOnly() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();
        String strong = etagOf(resourceSet, List.of("alpha")).replace("W/", "");

        Response response = handler.update(new RootContext(),
                withBody(request("If-None-Match", strong), created("renamed")));

        // 5-E4 row 21, the write half: the same header is a 200 on the GET row above.
        assertThat(response.getStatus().getCode()).isEqualTo(412);
    }

    // ---------------------------------------------------------------- DELETE

    @Test
    public void aDeleteWithoutIfMatchIs400WithTheDeleteWording() throws Exception {
        onItem();

        assertThatThrownBy(() -> handler.delete(new RootContext(), request()))
                .isInstanceOf(ServerException.class)
                // 5-E4 row 6: the same rule as row 4, one word different -- so dropping the prefix is a red
                // row on the destructive verb too.
                .hasMessage("precondition_failed (512) - Require If-Match header to delete Resource Set");
        verify(store, never()).delete(anyString(), anyString());
    }

    @Test
    public void aDeleteWithAMatchingIfMatchIs204WithABareContentTypeAndNoBody() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();

        Response response = handler.delete(new RootContext(),
                request("If-Match", etagOf(resourceSet, List.of("alpha"))));

        assertThat(response.getStatus().getCode()).isEqualTo(204);
        assertThat(response.getEntity().isRawContentEmpty()).isTrue();
        // ⚠ 5-E4 row 14 lists 204 among the bare application/json statuses: a Content-Type on a bodiless
        // response, which is odd enough that a port naturally omits it.
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json");
        assertThat(response.getHeaders().getFirst("ETag")).isNull();
        verify(hook).resourceSetDeleted(eq(REALM), any(ResourceSetDescription.class));
        verify(labelRegistration).updateLabelsForDeletedResourceSet(any(ResourceSetDescription.class));
        verify(store).delete(RSID, OWNER);
    }

    @Test
    public void aDeleteWithAStaleIfMatchDeletesNothing() throws Exception {
        readableWithLabels("alpha");
        onItem();

        Response response = handler.delete(new RootContext(), request("If-Match", "W/\"12345\""));

        assertThat(response.getStatus().getCode()).isEqualTo(412);
        verify(store, never()).delete(anyString(), anyString());
    }

    // ---------------------------------------------------------------- the catch-all Restlet had

    @Test
    public void anUnexpectedRuntimeExceptionBecomesA400ServerErrorNotA500() throws Exception {
        onItem();
        when(store.read(RSID, OWNER)).thenThrow(new IllegalStateException("the store fell over"));

        assertThatThrownBy(() -> handler.readOrList(new RootContext(), request()))
                .isInstanceOf(ServerException.class)
                // ⚠ 5-E4 row 9. Restlet's doCatch funnelled EVERY throwable here, and the message is the
                // engine's generic 500 sentence rather than the exception's -- so the original text is lost
                // on the wire and only reaches the log. Without this the base class answers a CREST 500.
                .hasMessage("Internal Server Error (500) - The server encountered an unexpected condition "
                        + "which prevented it from fulfilling the request");
    }

    @Test
    public void aConditionalWriteOnTheCollectionGivesRow9sThreeAnswers() throws Exception {
        onCollection();
        when(store.query(any())).thenReturn(new LinkedHashSet<>());

        // `*` passes the tag-less gate, so the verb body runs -- and reaches store.read(null, owner), which
        // is what produces row 9's 400. The mock returns null and NPEs, exactly as the real store throws.
        assertThatThrownBy(() -> handler.update(new RootContext(),
                withBody(request("If-Match", "*"), created("renamed"))))
                .isInstanceOf(ServerException.class)
                .hasMessageStartingWith("Internal Server Error (500)");

        // a concrete tag cannot match a representation with no tag
        assertThat(handler.update(new RootContext(), withBody(request("If-Match", "W/\"1\""), created("renamed")))
                .getStatus().getCode()).isEqualTo(412);

        // and absent is the missing-header rejection
        assertThatThrownBy(() -> handler.update(new RootContext(), withBody(request(), created("renamed"))))
                .isInstanceOf(ServerException.class)
                .hasMessageStartingWith("precondition_failed (512)");
    }

    @Test
    public void bothHeadersAreEvaluatedAndIfMatchWinningDoesNotSpareIfNoneMatch() throws Exception {
        ResourceSetDescription resourceSet = readableWithLabels("alpha");
        onItem();
        String etag = etagOf(resourceSet, List.of("alpha"));

        Response response = handler.readOrList(new RootContext(),
                request("If-Match", etag, "If-None-Match", etag));

        // 5-E4 row 18 measured this on a PUT (412); on a GET the same both-headers request is the 304.
        assertThat(response.getStatus().getCode()).isEqualTo(304);
    }

}
