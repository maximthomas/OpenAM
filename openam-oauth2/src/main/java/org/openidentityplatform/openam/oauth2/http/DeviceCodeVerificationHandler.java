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

import static org.forgerock.oauth2.core.Utils.isEmpty;
import static org.forgerock.openam.oauth2.OAuth2Constants.Custom.DECISION;
import static org.forgerock.openam.oauth2.OAuth2Constants.Custom.SAVE_CONSENT;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.inject.Inject;

import freemarker.template.TemplateException;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.CsrfProtection;
import org.forgerock.oauth2.core.DeviceCode;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.ResourceOwner;
import org.forgerock.oauth2.core.ResourceOwnerSessionValidator;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.core.Utils;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2Utils;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.services.context.Context;
import org.forgerock.util.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CHF OAuth2 device-flow verification endpoint ({@code /oauth2/device/user}), porting the Restlet
 * {@code DeviceCodeVerificationResource}.
 *
 * <p>The one browser endpoint of 5b-2: its {@code doCatch} called the <strong>4-argument</strong>
 * {@code ExceptionHandler.handle}, so its errors are the HTML error page, not JSON (D1, confirmed on the live
 * wire by 5-E3 row 3).
 */
public class DeviceCodeVerificationHandler extends AbstractOAuth2HttpBrowserEndpoint {

    /** {@code :223-224} asks the template factory for these paths verbatim -- no display folder (D4). */
    private static final String FORM = "templates/CodeVerificationForm.ftl";
    private static final String THANKS_PAGE = "templates/CodeThanks.ftl";
    private static final String NOT_FOUND = "not_found";

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");

    @Inject
    private FreemarkerTemplateRenderer templateRenderer;
    @Inject
    private BaseURLProviderFactory baseURLProviderFactory;
    @Inject
    private TokenStore tokenStore;
    @Inject
    private AuthorizationService authorizationService;
    @Inject
    private OAuth2ProviderSettingsFactory providerSettingsFactory;
    @Inject
    private ClientRegistrationStore clientRegistrationStore;
    @Inject
    private ResourceOwnerSessionValidator resourceOwnerSessionValidator;
    @Inject
    private CsrfProtection csrfProtection;
    @Inject
    private ConsentPageRenderer consentPageRenderer;

    /**
     * Renders the code-entry form, or -- when the URL already carries a {@code user_code} -- takes the same
     * path as the POST, exactly as {@code userCodeForm():265-274} delegates to {@code verify(null)}.
     *
     * @param ctx the request context.
     * @param request the CHF request.
     * @return the form, the thanks page, or the consent page.
     * @throws OAuth2Exception mapped to a redirect or the HTML error page by the base handler.
     */
    @Get
    public Response userCodeForm(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        return o2.getParameter(OAuth2Constants.DeviceCode.USER_CODE) == null
                ? page(FORM, o2, null)
                : verify(o2, request);
    }

    /**
     * Carries the resource owner's decision, or an unattended verification, back from the device page.
     *
     * <p>No content-type guard, unlike {@code AuthorizeHandler}: {@code OAuth2RouterProvider} never wrapped this
     * route in an {@code OAuth2Filter}, so there is no {@code validateContentType} to reproduce and adding one
     * would turn today's 200 into a 400 (finding 9).
     *
     * @param ctx the request context.
     * @param request the CHF request, whose form body carries {@code decision}, {@code save_consent} and
     *     {@code csrf}.
     * @return the form, the thanks page, or the consent page.
     * @throws OAuth2Exception mapped to a redirect or the HTML error page by the base handler.
     */
    @Post
    public Response verify(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        return verify(requestFactory.create(ctx, request), request);
    }

    /**
     * {@code verify():128-209}, the single body both verbs share.
     *
     * <p>Only two of Restlet's catch clauses survive as code. {@code ResourceOwnerConsentRequired} is not an
     * {@link OAuth2Exception}, so it can never reach the base mapper and is caught here; the
     * {@code InvalidGrantException} catch stays wrapped tightly around {@code readDeviceCode}, because the same
     * type thrown later by {@code updateDeviceCode}/{@code deleteDeviceCode} must reach the base as an error
     * rather than being rendered as "code not found". Everything else -- {@code ResourceOwnerAuthenticationRequired}
     * (301), {@code InvalidClientException}/{@code RedirectUriMismatchException} (no redirect), any other
     * {@link OAuth2Exception} (redirect honouring {@code parameterLocation}), and {@code IllegalArgumentException}
     * (the unified non-redirecting 400 page, D7 of 5b-1) -- is what the browser base already does.
     */
    private Response verify(OAuth2Request o2, Request request) throws OAuth2Exception {
        DeviceCode deviceCode;
        try {
            deviceCode = tokenStore.readDeviceCode(o2.getParameter(OAuth2Constants.DeviceCode.USER_CODE), o2);
        } catch (InvalidGrantException unknownCode) {
            return page(FORM, o2, NOT_FOUND);
        }
        if (deviceCode == null || deviceCode.isIssued()) {
            return page(FORM, o2, NOT_FOUND);
        }

        seedAttributesFromDeviceCode(deviceCode, o2);

        OAuth2ProviderSettings providerSettings = providerSettingsFactory.get(o2);
        ClientRegistration clientRegistration =
                clientRegistrationStore.get(o2.getParameter(OAuth2Constants.Params.CLIENT_ID), o2);
        boolean requireConsent =
                !providerSettings.clientsCanSkipConsent() || !clientRegistration.isConsentImplied();

        if (!requireConsent) {
            authorize(deviceCode, o2);
            return page(THANKS_PAGE, o2, null);
        }

        String decision = o2.getParameter(DECISION);
        if (isEmpty(decision)) {
            try {
                authorizationService.authorize(o2);
            } catch (ResourceOwnerConsentRequired consentRequired) {
                return consentPage(consentRequired, o2, request);
            }
            return page(THANKS_PAGE, o2, null);
        }

        if (csrfProtection.isCsrfAttack(o2)) {
            logger.debug("Session id from consent request does not match users session");
            return csrfRefusal(o2);
        }
        // Inside this branch Restlet's `!requireConsent ||` and `requireConsent &&` guards are constant, so
        // the two decisions are just the literals -- and anything but "allow" is a refusal.
        if ("on".equalsIgnoreCase(o2.getParameter(SAVE_CONSENT))) {
            saveConsent(o2);
        }
        if ("allow".equalsIgnoreCase(decision)) {
            authorize(deviceCode, o2);
        } else {
            tokenStore.deleteDeviceCode(deviceCode.getClientId(), deviceCode.getDeviceCode(), o2);
        }
        return page(THANKS_PAGE, o2, null);
    }

    /** {@code :170-173} and {@code :181-184}, the same three statements both consent paths end in. */
    private void authorize(DeviceCode deviceCode, OAuth2Request o2) throws OAuth2Exception {
        deviceCode.setResourceOwnerId(resourceOwnerSessionValidator.validate(o2).getId());
        deviceCode.setAuthorized(true);
        tokenStore.updateDeviceCode(deviceCode, o2);
    }

    /** {@code saveConsent:211-221}: the scope stored is the validated one, never the raw parameter. */
    private void saveConsent(OAuth2Request o2) throws OAuth2Exception {
        OAuth2ProviderSettings providerSettings = providerSettingsFactory.get(o2);
        ResourceOwner resourceOwner = resourceOwnerSessionValidator.validate(o2);
        ClientRegistration clientRegistration =
                clientRegistrationStore.get(o2.getParameter(OAuth2Constants.Params.CLIENT_ID), o2);
        Set<String> scope = Utils.splitScope(o2.getParameter(OAuth2Constants.Params.SCOPE));
        Set<String> validatedScope =
                providerSettings.validateAuthorizationScope(clientRegistration, scope, o2);
        providerSettings.saveConsent(resourceOwner, clientRegistration.getClientId(), validatedScope);
    }

    private Response consentPage(ResourceOwnerConsentRequired consentRequired, OAuth2Request o2, Request request) {
        try {
            return consentPageRenderer.render(consentRequired, o2, request);
        } catch (IOException | TemplateException renderFailed) {
            return serverErrorPage(o2, renderFailed);
        }
    }

    /**
     * {@code :161}: a CSRF failure is 400 {@code bad_request} with a {@code null} description, and it is the
     * <strong>page</strong> -- the four-argument {@code OAuth2RestletException} passes {@code state}, not a
     * redirect (5-E3 row 3). Built rather than thrown so it cannot redirect: {@code bad_request} would be
     * redirectable, and this request's {@code redirect_uri} arrived on the wire unvalidated.
     */
    private Response csrfRefusal(OAuth2Request o2) {
        return withErrorHeaders(errorResponseFactory.toResponse(o2,
                OAuth2Error.of(400, "bad_request", null)
                        .withState(o2.<String>getParameter(OAuth2Constants.Params.STATE))));
    }

    /**
     * One of the two device pages at 200. The template path is resolved <strong>literally</strong>: unlike the
     * consent page, these two never went through the {@code ?display=} folder scheme, and
     * {@code templates/popup/CodeVerificationForm.ftl} does not exist to be found (D4).
     */
    @VisibleForTesting
    Response page(String template, OAuth2Request o2, String errorCode) {
        try {
            return FreemarkerTemplateRenderer.toHtmlResponse(Status.OK,
                    templateRenderer.render(template, pageModel(o2, errorCode)));
        } catch (IOException | TemplateException renderFailed) {
            return serverErrorPage(o2, renderFailed);
        }
    }

    /**
     * The same seam, and the same reasoning, as {@code AuthorizeHandler.serverErrorPage}: a broken template is
     * a deployment fault rather than one of the bug paths {@code decisions.md} D3 sends to the framework, so it
     * stays a contractual 400 page. Built rather than thrown, so it cannot redirect to a {@code redirect_uri}
     * that arrived on the wire and was never validated -- a device code stores none.
     */
    private Response serverErrorPage(OAuth2Request o2, Exception renderFailed) {
        return withErrorHeaders(errorResponseFactory.toResponse(o2,
                OAuth2Error.of(new ServerException(renderFailed))
                        .withState(o2.<String>getParameter(OAuth2Constants.Params.STATE))));
    }

    /**
     * The device pages' model, from {@code getTemplateRepresentation:223-235}: {@code baseUrl}, {@code locale}
     * and {@code realm}, plus {@code errorCode} when there is one.
     *
     * <p>An absent {@code errorCode} is <strong>omitted</strong>, not null-valued. Restlet put a null into a
     * {@code Map<String, String>}, which FreeMarker reads as missing; putting the key with a null value would
     * behave the same today and diverge the moment anything iterates the model.
     */
    @VisibleForTesting
    Map<String, Object> pageModel(OAuth2Request o2, String errorCode) {
        Map<String, Object> data = new HashMap<>();
        if (errorCode != null) {
            data.put("errorCode", errorCode);
        }
        String realm = o2.getParameter(OAuth2Constants.Custom.REALM);
        data.put("baseUrl", baseURLProviderFactory.get(realm).getRootURL(o2.getHttpServletRequest()));
        data.put("locale", OAuth2Utils.joinStatic(o2.getAcceptedLanguages(), " "));
        data.put("realm", realm);
        return data;
    }

    /**
     * Copies the device-code record onto the request attributes, reproducing
     * {@code DeviceCodeVerificationResource.addRequestParamsFromDeviceCode:239-257}.
     *
     * <p>Attributes rather than a local map because they are the first source {@link OAuth2Request#getParameter}
     * consults, which is what makes {@code providerSettingsFactory.get}, {@code clientRegistrationStore.get} and
     * {@code authorizationService.authorize} resolve against the device code rather than the wire (D3).
     */
    @SuppressWarnings("unchecked")
    void seedAttributesFromDeviceCode(DeviceCode deviceCode, OAuth2Request o2) {
        for (Map.Entry<String, Object> entry : ((Map<String, Object>) deviceCode.getObject()).entrySet()) {
            // Every value is a single-element list bar scope, which is the scope set (DeviceCode:64-83).
            List<String> values = (List<String>) entry.getValue();
            Object value = OAuth2Constants.Params.SCOPE.equals(entry.getKey())
                    ? OAuth2Utils.joinStatic(values, " ")
                    : values.iterator().next();
            // The one renamed key: the record stores "clientID", every reader asks for "client_id".
            String key = OAuth2Constants.CoreTokenParams.CLIENT_ID.equals(entry.getKey())
                    ? OAuth2Constants.Params.CLIENT_ID
                    : entry.getKey();
            o2.setAttribute(key, value);
        }
    }
}
