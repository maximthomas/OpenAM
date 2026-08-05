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

import static java.util.Collections.emptyList;

import jakarta.inject.Inject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.resources.ResourceSetStore;
import org.forgerock.oauth2.restlet.resources.ResourceSetDescriptionValidator;
import org.forgerock.oauth2.restlet.resources.ResourceSetRegistrationHook;
import org.forgerock.openam.cts.api.fields.ResourceSetTokenField;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Delete;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.http.annotations.Put;
import org.forgerock.openam.oauth2.ResourceSetDescription;
import org.forgerock.openam.oauth2.extensions.ExtensionFilterManager;
import org.forgerock.openam.oauth2.extensions.ResourceRegistrationFilter;
import org.forgerock.openam.oauth2.resources.ResourceSetLabelRegistration;
import org.forgerock.openam.oauth2.resources.labels.ResourceSetLabel;
import org.forgerock.openam.oauth2.resources.labels.UmaLabelsStore;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.services.context.Context;
import org.forgerock.util.query.QueryFilter;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CHF endpoint for OAuth2 resource servers to register the resource sets they protect
 * ({@code /oauth2/resource_set}), porting Restlet's {@code ResourceSetRegistrationEndpoint}.
 *
 * <p>The business logic is the Restlet endpoint's, moved verbatim -- including the two behaviours that look
 * like defects and are contract: the duplicate-name 400 is built <em>in band</em> rather than thrown, so it
 * keeps a reason <em>phrase</em> in its {@code error} field; and {@code labels} are stripped from the
 * description before the store call and re-added after it, which is what brackets the
 * {@code ResourceRegistrationFilter} extension points.
 *
 * <h2>What is <em>not</em> in the Restlet source, and has to be here</h2>
 * Restlet's {@code ServerResource} evaluated {@code If-Match} / {@code If-None-Match} itself, before the
 * annotated method ran; the endpoint's own Java only asked whether an {@code If-Match} was present. CHF has no
 * conditional-request support at all, so the port carries the whole precondition gate explicitly
 * ({@link #preconditions}), and it must be a gate over <strong>every</strong> verb rather than per-verb rules:
 * {@code doConditionalHandle} does not care which method it guards. See {@link HttpConditions} for the
 * comparison rules and phase-5c D6 for the measured rows behind each one.
 *
 * <h2>Errors</h2>
 * {@link AbstractOAuth2HttpJsonEndpoint} renders any {@link OAuth2Exception} as the OAuth2 JSON body at the
 * exception's own status. Restlet additionally funnelled <em>every other</em> throwable into a 400
 * {@code server_error} through its {@code doCatch}, which this class reproduces in {@link #guarded} -- see
 * that method for why a plain 500 would be a wire change.
 *
 * @see <a href="https://tools.ietf.org/html/draft-hardjono-oauth-resource-reg-04">OAuth 2.0 Resource Set
 *      Registration</a>
 */
public class ResourceSetRegistrationHandler extends AbstractOAuth2HttpJsonEndpoint {

    private static final String RESOURCE_SET_ID_KEY = "rsid";
    private static final String ID_FIELD = "_id";
    private static final String POLICY_URI_FIELD = "user_access_policy_uri";
    private static final String LABELS_FIELD = "labels";

    /**
     * 5-E4 row 14: this endpoint's responses are bare {@code application/json}, with no charset -- stamped at
     * three sites here (the two below and {@link #withErrorHeaders}, which covers the thrown errors). The 405
     * and 412 bodies are the exception: they are written by {@link ResourceSetErrorFilter}, which stamps its
     * own. Row 7's duplicate-name 400 is the other exception, and keeps a charset on purpose.
     */
    private static final String JSON_TYPE = "application/json";

    /** CHF's {@code Status} names neither of the two the conditional gate answers with. */
    private static final Status NOT_MODIFIED = Status.valueOf(304);
    private static final Status PRECONDITION_FAILED = Status.valueOf(412);

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");

    @Inject
    private OAuth2ProviderSettingsFactory providerSettingsFactory;
    @Inject
    private ResourceSetDescriptionValidator validator;
    @Inject
    private Set<ResourceSetRegistrationHook> hooks;
    @Inject
    private ResourceSetLabelRegistration labelRegistration;
    @Inject
    private ExtensionFilterManager extensionFilterManager;
    @Inject
    private UmaLabelsStore umaLabelsStore;

    /**
     * Reads one resource set description, or lists the ids of the client's resource sets when the URL carries
     * no {@code rsid}.
     *
     * @param ctx the request context.
     * @param request the CHF request, whose conditional headers this method honours.
     * @return 200 with the description or the id array; 304 or 412 if a precondition decides otherwise.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Get
    public Response readOrList(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        return guarded(() -> {
            OAuth2Request o2 = requestFactory.create(ctx, request);
            ReadModel model = readOrListModel(o2);
            HttpConditions conditions = HttpConditions.of(request);

            if (conditions.hasIfMatch() && !conditions.matches(model.etag)) {
                // ⚠ 5-E4 rows 3b and 20: a GET's 412 carries the representation, because Restlet had already
                // produced it to obtain the tag. ResourceSetErrorFilter leaves a non-empty entity alone, so
                // this really does reach the client as a 200-shaped body under a 412.
                return respond(PRECONDITION_FAILED, model);
            }
            if (conditions.hasIfNoneMatch() && conditions.noneMatches(model.etag, true)) {
                // 5-E4 row 3: the ETag rides along and there is no Content-Type at all, so no entity is set.
                Response response = new Response(NOT_MODIFIED);
                return withEtag(response, model.etag);
            }
            return respond(Status.OK, model);
        });
    }

    /**
     * Creates a resource set description. The {@code rsid} in the URL, if any, is ignored -- all three
     * Restlet attachments reached the same {@code @Post}, so a create against an item URL mints a new id
     * (5-E4 row 16).
     *
     * @param ctx the request context.
     * @param request the CHF request carrying the description.
     * @return 201 with the id, the policy URI and an ETag; the in-band 400 on a duplicate name; 412 if a
     *     precondition refuses the create.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Post
    public Response create(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        return guarded(() -> {
            OAuth2Request o2 = requestFactory.create(ctx, request);
            Response refused = preconditions(o2, request);
            if (refused != null) {
                return refused;
            }
            ResourceSetDescription resourceSet = new ResourceSetDescription(null, clientId(o2), resourceOwnerId(o2),
                    validator.validate(requestBody(request)));
            ResourceSetStore store = store(o2);

            QueryFilter<String> duplicate = QueryFilter.and(
                    QueryFilter.equalTo(ResourceSetTokenField.NAME, resourceSet.getName()),
                    QueryFilter.equalTo(ResourceSetTokenField.CLIENT_ID, clientId(o2)),
                    QueryFilter.equalTo(ResourceSetTokenField.RESOURCE_OWNER_ID, resourceOwnerId(o2)));
            if (!store.query(duplicate).isEmpty()) {
                // ⚠ Built in band rather than thrown, so it keeps Restlet's reason PHRASE in the `error`
                // field where every other error on this endpoint carries an OAuth2 error code -- and it is
                // the one response that carries a charset at all (5-E4 rows 7 and 14). Both are contract.
                // ⚠ Left as setJson writes it, which is the point: the post-flip capture measured this response
                // as `application/json;charset=UTF-8`, byte-identical to Restlet's row 7. Parity, not a
                // divergence -- so withErrorHeaders below must NOT be allowed to reach it, and nothing may
                // normalise this endpoint's Content-Type wholesale.
                return new Response(Status.BAD_REQUEST).setEntity(OAuth2Error.of(400, "Bad Request",
                        "A shared item with the name '" + resourceSet.getName() + "' already exists").asMap());
            }

            // ⚠ The strip/re-add is not an implementation detail to tidy: it BRACKETS the extension points,
            // and the order below is the contract a customer's ResourceRegistrationFilter is written
            // against. Nothing in-tree implements that SPI, so no test will tell you if it moves.
            JsonValue labels = resourceSet.getDescription().get(LABELS_FIELD);
            resourceSet.getDescription().remove(LABELS_FIELD);
            for (ResourceRegistrationFilter filter : registrationFilters()) {
                filter.beforeResourceRegistration(resourceSet);       // no labels, no _id, no policyUri
            }
            store.create(o2, resourceSet);                            // assigns the id and the policy uri
            resourceSet.getDescription().add(LABELS_FIELD, labels.isNotNull() ? labels.getObject() : emptyList());
            labelRegistration.updateLabelsForNewResourceSet(resourceSet);
            for (ResourceRegistrationFilter filter : registrationFilters()) {
                filter.afterResourceRegistration(resourceSet);        // everything populated
            }
            for (ResourceSetRegistrationHook hook : hooks) {
                hook.resourceSetCreated(o2.<String>getParameter("realm"), resourceSet);
            }
            return respond(Status.CREATED, new ReadModel(representation(resourceSet, false), etag(resourceSet)));
        });
    }

    /**
     * Replaces a resource set description. Requires an {@code If-Match}: without one the request is rejected
     * whatever else it carries.
     *
     * @param ctx the request context.
     * @param request the CHF request carrying the replacement description.
     * @return 200 with the id and the new ETag; 412 if a precondition refuses the update.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Put
    public Response update(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        return guarded(() -> {
            OAuth2Request o2 = requestFactory.create(ctx, request);
            Response refused = preconditions(o2, request);
            if (refused != null) {
                return refused;
            }
            requireIfMatch(request, "update");

            Map<String, Object> attributes = validator.validate(requestBody(request));
            ResourceSetStore store = store(o2);
            // The second read of the request: the gate already performed one to obtain the tag, exactly as
            // Restlet's conditional layer invoked the @Get before dispatching to the @Put.
            ResourceSetDescription resourceSet = store.read(resourceSetId(o2), resourceOwnerId(o2))
                    .update(attributes);

            JsonValue labels = resourceSet.getDescription().get(LABELS_FIELD);
            resourceSet.getDescription().remove(LABELS_FIELD);
            store.update(resourceSet);
            resourceSet.getDescription().add(LABELS_FIELD, labels.isNotNull() ? labels.getObject() : emptyList());
            // ⚠ Driven from the REQUEST body, so an update that does not resend `labels` deletes them --
            // changing the GET body and, since labels are in the hash, the ETag (5-E4 row 2a).
            labelRegistration.updateLabelsForExistingResourceSet(resourceSet);

            return respond(Status.OK, new ReadModel(representation(resourceSet, false), etag(resourceSet)));
        });
    }

    /**
     * Removes a resource set description. Requires an {@code If-Match}, like {@link #update}.
     *
     * @param ctx the request context.
     * @param request the CHF request.
     * @return 204 with no body; 412 if a precondition refuses the delete.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Delete
    public Response delete(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        return guarded(() -> {
            OAuth2Request o2 = requestFactory.create(ctx, request);
            Response refused = preconditions(o2, request);
            if (refused != null) {
                return refused;
            }
            requireIfMatch(request, "delete");

            ResourceSetStore store = store(o2);
            ResourceSetDescription resourceSet = store.read(resourceSetId(o2), resourceOwnerId(o2));
            for (ResourceSetRegistrationHook hook : hooks) {
                hook.resourceSetDeleted(o2.<String>getParameter("realm"), resourceSet);
            }
            labelRegistration.updateLabelsForDeletedResourceSet(resourceSet);
            store.delete(resourceSetId(o2), resourceOwnerId(o2));

            Response response = new Response(Status.NO_CONTENT);
            // ⚠ 5-E4 row 14 lists 204 among the bare application/json statuses -- a Content-Type on a
            // response with no body, which a port naturally omits.
            response.getHeaders().put(ContentTypeHeader.NAME, JSON_TYPE);
            return response;
        });
    }

    // ---------------------------------------------------------------- the precondition gate

    /**
     * Restlet's {@code doConditionalHandle}, which ran before <strong>every</strong> annotated method: if
     * either conditional header is present it obtains the current tag by invoking the {@code @Get}, compares,
     * and answers 412 rather than dispatching.
     *
     * <p>The "either header present" guard is load-bearing, not an optimisation: without it every request
     * would read the addressed resource set, and 5-E4 row 16's create-at-an-item-url would 404 instead of
     * creating.
     *
     * <p>A {@code GET} does <em>not</em> use this method -- it needs the representation in hand either way,
     * and its two answers differ (304, and a 412 that carries the body). See {@link #readOrList}.
     *
     * @return {@code null} to let the verb proceed, or the bare 412 whose body {@code ResourceSetErrorFilter}
     *     fills in.
     */
    private Response preconditions(OAuth2Request o2, Request request) throws OAuth2Exception {
        HttpConditions conditions = HttpConditions.of(request);
        if (!conditions.hasIfMatch() && !conditions.hasIfNoneMatch()) {
            return null;
        }
        String etag = readOrListModel(o2).etag;
        if (conditions.hasIfMatch() && !conditions.matches(etag)) {
            return new Response(PRECONDITION_FAILED);
        }
        // ⚠ Evaluated even when If-Match just passed -- both headers can fail one request (5-E4 row 18) --
        // and with checkWeakness = false, because this is never a GET (row 21).
        if (conditions.hasIfNoneMatch() && conditions.noneMatches(etag, false)) {
            return new Response(PRECONDITION_FAILED);
        }
        return null;
    }

    /**
     * The endpoint's own check, which asks only whether an {@code If-Match} was <em>sent</em> -- the matching
     * having already been done by the gate above.
     *
     * <p>⚠ The message is Restlet's {@code ResourceException} formatting, {@code "<reason> (<code>) -
     * <description>"}, and it reaches the wire verbatim inside {@code error_description} because the mapper
     * passed {@code getMessage()} through untouched. So {@code 512} never reaches the status -- the status is
     * 400 {@code server_error}, {@code ServerException}'s own -- but both {@code 512} and
     * {@code precondition_failed} do reach the client, in the text (5-E4 rows 4 and 6).
     */
    private static void requireIfMatch(Request request, String verb) throws ServerException {
        if (!HttpConditions.of(request).hasIfMatch()) {
            throw new ServerException("precondition_failed (512) - Require If-Match header to " + verb
                    + " Resource Set");
        }
    }

    @SuppressWarnings("unchecked")
    private Iterable<ResourceRegistrationFilter> registrationFilters() {
        return extensionFilterManager.getFilters(ResourceRegistrationFilter.class);
    }

    /**
     * The request body as a map, parsed the way Restlet's {@code toMap} parsed it: {@code org.json} first,
     * then Jackson over its re-serialisation.
     *
     * <p>⚠ The double parse is not redundant. {@code org.json}'s message <em>is</em> the wire contract for a
     * malformed body (5-E4 row 12 asserts it exactly) and Jackson's differs; and an unparseable body has to
     * become a {@code BadRequestException} rather than the {@link JsonException} Jackson's wrapper throws,
     * which is unchecked and would be swallowed by {@link #guarded} into the wrong error entirely.
     *
     * <p>⚠ <b>And the parser is a wire contract, not a style choice.</b> Restlet reaches
     * {@code new JSONObject(<raw body>)}, so the endpoint inherits org.json's <em>leniency</em>: 5-E4 row 22
     * measured single-quoted strings, unquoted keys and a trailing comma all answering <b>201</b>, while
     * duplicate keys answer <b>400</b> where Jackson would take the last value. Parsing with Jackson alone --
     * the obvious simplification -- changes five measured outcomes and switches off resource servers that
     * work today, with a plausible-looking 400 that points nowhere near the cause. Filed as <b>T8</b> in
     * phase-5c.md, to be done deliberately after the flip.
     *
     * <p>It also solves a problem the plan raised separately: {@code Entity.getJson()} memoises, so the map
     * {@code ChfOAuth2Request.getBody()} hands out is the same instance the audit filter parsed, and the
     * {@code labels} strip/re-add above would write through to it. Parsing from the raw string yields a fresh
     * map, exactly as Restlet's did -- and {@code Entity.getString()} brackets its read with
     * {@code push()}/{@code pop()}, so it does not disturb the entity for anyone else.
     */
    private static Map<String, Object> requestBody(Request request) throws OAuth2Exception {
        String json;
        try {
            json = request.getEntity().getString();
        } catch (IOException e) {
            throw new BadRequestException(e.getMessage());
        }
        if (StringUtils.isEmpty(json)) {
            return Collections.emptyMap();          // Restlet's `entity == null` branch
        }
        try {
            return JsonValueBuilder.toJsonValue(new JSONObject(json).toString()).asMap(Object.class);
        } catch (JSONException e) {
            throw new BadRequestException(e.getMessage());
        }
    }

    // ---------------------------------------------------------------- the read model, and the tag it yields

    /** The entity Restlet's {@code @Get} produced and the {@code Tag} its conditional layer then compared. */
    private static final class ReadModel {

        private final Object body;
        /** {@code null} at the collection URL -- the list representation carries no tag (5-E4 row 5). */
        private final String etag;

        private ReadModel(Object body, String etag) {
            this.body = body;
            this.etag = etag;
        }
    }

    /**
     * Restlet's {@code readOrListResourceSet}, which is reached from all four verbs -- directly on a
     * {@code GET}, and through the conditional layer on the others, which invoked it purely to obtain the tag.
     *
     * <p>⚠ The item branch rebuilds the <em>read</em> model, whose {@code labels} come from
     * {@link UmaLabelsStore} rather than from the store row or the request body. Hashing the bare
     * {@code store.read} instead yields a different tag for every labelled resource set, so every conditional
     * request from a real client would 412 (phase-5c finding 17, measured by 5-E4 row 2b).
     */
    private ReadModel readOrListModel(OAuth2Request o2) throws OAuth2Exception {
        String resourceSetId = resourceSetId(o2);
        if (resourceSetId == null || resourceSetId.isEmpty()) {
            return new ReadModel(listResourceSetIds(o2), null);
        }
        ResourceSetDescription resourceSet = readResourceSet(o2, resourceSetId);
        return new ReadModel(representation(resourceSet, true), etag(resourceSet));
    }

    private ResourceSetDescription readResourceSet(OAuth2Request o2, String resourceSetId) throws OAuth2Exception {
        ResourceSetDescription resourceSet = store(o2).read(resourceSetId, resourceOwnerId(o2));
        List<String> labels = new ArrayList<>();
        try {
            for (ResourceSetLabel label : umaLabelsStore.forResourceSet(resourceSet.getRealm(),
                    resourceSet.getResourceOwnerId(), resourceSet.getId(), false)) {
                labels.add(label.getName());
            }
        } catch (org.forgerock.json.resource.ResourceException e) {
            throw new ServerException(e);
        }
        // ⚠ Set-iteration order, not sorted: UmaLabelsStore.query returns a HashSet and List.hashCode is
        // order-sensitive, so sorting here would look like a cleanup and invalidate every ETag in the field.
        resourceSet.getDescription().put(LABELS_FIELD, labels);
        return resourceSet;
    }

    private Set<String> listResourceSetIds(OAuth2Request o2) throws OAuth2Exception {
        QueryFilter<String> query = QueryFilter.and(
                QueryFilter.equalTo(ResourceSetTokenField.CLIENT_ID, clientId(o2)),
                QueryFilter.equalTo(ResourceSetTokenField.RESOURCE_OWNER_ID, resourceOwnerId(o2)));
        Set<String> ids = new HashSet<>();
        for (ResourceSetDescription resourceSet : store(o2).query(query)) {
            ids.add(resourceSet.getId());
        }
        // A HashSet, so the array's order is unspecified -- assert membership, never sequence.
        return ids;
    }

    /**
     * {@code generateETag}, ported verbatim, weak tag and all.
     *
     * <p>The {@code !isDefined(labels)} round-trip is <strong>unreachable on every response path</strong> --
     * all three callers define {@code labels} first -- and is reproduced anyway, because removing it is a
     * behaviour change nobody can prove safe and the value is a client's concurrency token. Do not reformat
     * it: no {@code Math.abs}, no padding, no digest. The hash is JLS-specified all the way down, which is
     * what lets an ETag issued before an upgrade still match after one.
     */
    private static String etag(ResourceSetDescription resourceSet) {
        int hashCode = resourceSet.hashCode();
        if (!resourceSet.getDescription().isDefined(LABELS_FIELD)) {
            resourceSet.getDescription().put(LABELS_FIELD, null);
            hashCode = resourceSet.hashCode();
            resourceSet.getDescription().remove(LABELS_FIELD);
        }
        return "W/\"" + hashCode + "\"";
    }

    /** {@code createJsonResponse}'s body: the id, optionally the whole description, and the policy URI. */
    private static Map<String, Object> representation(ResourceSetDescription resourceSet, boolean includeResourceSet) {
        Map<String, Object> body = includeResourceSet
                ? new LinkedHashMap<>(resourceSet.asMap())
                : new LinkedHashMap<>();
        body.put(ID_FIELD, resourceSet.getId());
        if (resourceSet.getPolicyUri() != null) {
            body.put(POLICY_URI_FIELD, resourceSet.getPolicyUri());
        }
        return body;
    }

    // ---------------------------------------------------------------- plumbing

    /**
     * The third {@link #JSON_TYPE} stamp site, covering the errors this endpoint <em>throws</em>: the base
     * class renders those through {@code setEntity(Map)}, which writes a charset, and row 14 measured them
     * bare (the {@code PUT} 400 and the {@code GET} 404).
     * <p>
     * ⚠ Deliberately not the whole endpoint: the in-band duplicate-name 400 is returned normally, never passes
     * through {@code onError}, and keeps its charset because row 7 measured one. That is also why this cannot
     * be a filter -- by the time {@link ResourceSetErrorFilter} sees them, the two are both OAuth2-shaped 4xx
     * bodies with a charset and nothing tells them apart.
     */
    @Override
    protected Response withErrorHeaders(Response response) {
        response.getHeaders().put(ContentTypeHeader.NAME, JSON_TYPE);
        return response;
    }

    private Response respond(Status status, ReadModel model) {
        Response response = new Response(status).setEntity(model.body);
        // setEntity -> setJson writes "application/json; charset=UTF-8"; row 14 measured it bare and the
        // gate asserts it with toBe. One line after the body, on every response that has one.
        response.getHeaders().put(ContentTypeHeader.NAME, JSON_TYPE);
        return withEtag(response, model.etag);
    }

    private static Response withEtag(Response response, String etag) {
        if (etag != null) {
            response.getHeaders().put("ETag", etag);
        }
        return response;
    }

    private ResourceSetStore store(OAuth2Request o2) throws OAuth2Exception {
        return providerSettingsFactory.get(o2).getResourceSetStore();
    }

    private static String resourceSetId(OAuth2Request o2) {
        return (String) o2.getAttribute(RESOURCE_SET_ID_KEY);
    }

    private static String clientId(OAuth2Request o2) {
        return o2.getToken(AccessToken.class).getClientId();
    }

    private static String resourceOwnerId(OAuth2Request o2) {
        return o2.getToken(AccessToken.class).getResourceOwnerId();
    }

    /** A handler method body, which may fail the way the endpoint's collaborators fail. */
    private interface Body {
        Response run() throws OAuth2Exception;
    }

    /**
     * Restlet's {@code doCatch}, which caught {@link Throwable} and handed it to a mapper whose fall-through
     * was {@code new ServerException(throwable)} -- i.e. <strong>400 {@code server_error}</strong>, with the
     * message of the {@code ResourceException} the engine had wrapped it in.
     *
     * <p>{@link AbstractOAuth2HttpJsonEndpoint} deliberately lets an unexpected throwable fall to the
     * framework's CREST 500, which is right for the other OAuth2 endpoints and wrong here: 5-E4 row 9 measured
     * a real request -- {@code PUT /oauth2/resource_set} with {@code If-Match: *}, which reaches
     * {@code store.read(null, owner)} -- answering that 400. Reproducing it costs this method; not
     * reproducing it costs an e2e edit and a divergence row.
     */
    private Response guarded(Body body) throws OAuth2Exception {
        try {
            return body.run();
        } catch (RuntimeException e) {
            // The message is the engine's, not this exception's, so the stack trace would otherwise be lost.
            logger.warn("Unhandled exception in /oauth2/resource_set", e);
            // OAuth2Error.RESTLET_INTERNAL_ERROR: authored here, so it survives the D8 mask -- and shared with
            // it so the one measured sentence has one spelling.
            throw new ServerException(OAuth2Error.RESTLET_INTERNAL_ERROR);
        }
    }
}
