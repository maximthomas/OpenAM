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
 * Portions copyright 2025-2026 3A Systems LLC.
 */

package org.forgerock.openam.uma;

import jakarta.inject.Inject;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.oauth2.ResourceSetDescription;
import org.forgerock.oauth2.resources.ResourceSetStore;
import org.forgerock.openam.oauth2.extensions.ExtensionFilterManager;
import org.forgerock.openam.uma.extensions.PermissionRequestFilter;
import org.forgerock.services.context.Context;
import org.openidentityplatform.openam.uma.AbstractUmaHttpEndpoint;

/**
 * Endpoint for UMA resource servers to register client attempts to access a protected resource.
 *
 * @since 13.0.0
 */
public class PermissionRequestEndpoint extends AbstractUmaHttpEndpoint {

    private final OAuth2ProviderSettingsFactory providerSettingsFactory;
    private final OAuth2RequestFactory requestFactory;
    private final UmaProviderSettingsFactory umaProviderSettingsFactory;
    private final ExtensionFilterManager extensionFilterManager;

    /**
     * Constructs a new PermissionRequestEndpoint instance
     * @param providerSettingsFactory An instance of the OAuth2ProviderSettingsFactory.
     * @param requestFactory An instance of the OAuth2RequestFactory.
     * @param umaProviderSettingsFactory An instance of the UmaProviderSettingsFactory.
     * @param extensionFilterManager An instance of the ExtensionFilterManager.
     */
    @Inject
    public PermissionRequestEndpoint(OAuth2ProviderSettingsFactory providerSettingsFactory,
            OAuth2RequestFactory requestFactory, UmaProviderSettingsFactory umaProviderSettingsFactory,
            ExtensionFilterManager extensionFilterManager) {
        this.providerSettingsFactory = providerSettingsFactory;
        this.requestFactory = requestFactory;
        this.umaProviderSettingsFactory = umaProviderSettingsFactory;
        this.extensionFilterManager = extensionFilterManager;
    }

    /**
     * Registers the permission that the client requires for it to be able to access a protected resource.
     *
     * @param context The request context.
     * @param request The CHF request carrying the permission request JSON body.
     * @return A 201 response containing the permission ticket.
     * @throws UmaException If the JSON request body is invalid or the requested resource set does not exist.
     */
    @Post
    public Response registerPermissionRequest(@Contextual Context context, @Contextual Request request)
            throws UmaException, NotFoundException, ServerException {
        OAuth2Request oAuth2Request = requestFactory.create(context, request);
        JsonValue permissionRequest = oAuth2Request.getBody();
        String resourceSetId = getResourceSetId(permissionRequest);
        String clientId = getClientId(oAuth2Request);
        OAuth2ProviderSettings providerSettings = providerSettingsFactory.get(oAuth2Request);
        String resourceOwnerId = getResourceOwnerId(oAuth2Request);
        ResourceSetDescription resourceSetDescription = getResourceSet(resourceSetId, resourceOwnerId,
                providerSettings);
        Set<String> scopes = validateScopes(permissionRequest, resourceSetDescription);
        for (PermissionRequestFilter filter : extensionFilterManager.getFilters(PermissionRequestFilter.class)) {
            filter.onPermissionRequest(resourceSetDescription, scopes, clientId);
        }
        String ticket = umaProviderSettingsFactory.get(oAuth2Request).getUmaTokenStore()
                .createPermissionTicket(resourceSetId, scopes, clientId).getId();
        // setEntity(Map) -> application/json; charset=UTF-8.
        return new Response(Status.valueOf(201)).setEntity(Collections.<String, Object>singletonMap("ticket", ticket));
    }

    private String getResourceSetId(JsonValue permissionRequest) throws UmaException {
        JsonValue resourceSetId = permissionRequest.get("resource_set_id");
        try {
            resourceSetId.required();
        } catch (JsonValueException e) {
            throw new UmaException(400, "invalid_resource_set_id",
                    "Invalid Permission Request. Missing required attribute, 'resource_set_id'.");
        }
        if (!resourceSetId.isString()) {
            throw new UmaException(400, "invalid_resource_set_id",
                    "Invalid Permission Request. Required attribute, 'resource_set_id', must be a String.");
        }
        return resourceSetId.asString();
    }

    private Set<String> validateScopes(JsonValue permissionRequest, ResourceSetDescription resourceSetDescription)
            throws UmaException {

        Collection<String> permissionScopes = getScopes(permissionRequest);

        JsonValue scopes = resourceSetDescription.getDescription().get("scopes");
        if (!scopes.asCollection(String.class).containsAll(permissionScopes)) {
            throw new UmaException(400, "invalid_scope",
                    "Requested scopes are not in allowed scopes for resource set.");
        }

        return new HashSet<>(permissionScopes);
    }

    private List<String> getScopes(JsonValue permissionRequest) throws UmaException {
        try {
            permissionRequest.get("scopes").required();
        } catch (JsonValueException e) {
            throw new UmaException(400, "invalid_scope",
                    "Invalid Permission Request. Missing required attribute, 'scopes'.");
        }
        try {
            return permissionRequest.get("scopes").asList(String.class);
        } catch (JsonValueException e) {
            throw new UmaException(400, "invalid_scope",
                    "Invalid Permission Request. Required attribute, 'scopes', must be an array of Strings.");
        }
    }

    private ResourceSetDescription getResourceSet(String resourceSetId, String resourceOwnerId, OAuth2ProviderSettings providerSettings) throws UmaException {
        try {
            ResourceSetStore store = providerSettings.getResourceSetStore();
            return store.read(resourceSetId, resourceOwnerId);
        } catch (NotFoundException e) {
            throw new UmaException(400, "invalid_resource_set_id", "Could not find Resource Set, " + resourceSetId);
        } catch (ServerException e) {
            throw new UmaException(400, "invalid_resource_set_id", e.getMessage());
        }
    }

    private String getClientId(OAuth2Request request) throws ServerException {
        return request.getToken(AccessToken.class).getClientId();
    }

    private String getResourceOwnerId(OAuth2Request request) {
        return request.getToken(AccessToken.class).getResourceOwnerId();
    }
}
