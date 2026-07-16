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
 * Copyright 2012-2016 ForgeRock AS.
 * Portions Copyrighted 2019 Open Source Solution Technology Corp.
 * Portions copyright 2025-2026 3A Systems LLC.
 */

package org.forgerock.openam.oauth2;

import static org.forgerock.openam.utils.JsonValueBuilder.toJsonValue;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;

import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.openam.oauth2.OAuth2Constants.ProofOfPossession;
import org.forgerock.util.encode.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuth2Utils {

    public static final Logger DEBUG = LoggerFactory.getLogger("OAuth2Provider");

    public static final String SCOPE_DELIMITER = " ";

    /**
     * Gets the deployment URI of the OAuth2 authorization server
     * @param request the request to get the deployment uri of
     * @return the deployment URI of the OAuth2 authorization server.
     */
    public String getDeploymentURL(HttpServletRequest request){
        String uri = request.getRequestURI();
        String deploymentURI = uri;
        int firstSlashIndex = uri.indexOf("/");
        int secondSlashIndex = uri.indexOf("/", firstSlashIndex + 1);
        if (secondSlashIndex != -1) {
            deploymentURI = uri.substring(0, secondSlashIndex);
        }
        StringBuffer sb = new StringBuffer(100);
        sb.append(request.getScheme()).append("://")
                .append(request.getServerName()).append(":")
                .append(request.getServerPort())
                .append(deploymentURI);
        return sb.toString();
    }

    /**
     * Determines if a string is empty. Empty is defined as null or empty
     * string.
     *
     * <pre>
     *  OAuth2Utils.isEmpty(null)               = true
     *  OAuth2Utils.isEmpty(&quot;&quot;)       = true
     *  OAuth2Utils.isEmpty(&quot; &quot;)      = false
     *  OAuth2Utils.isEmpty(&quot;bob&quot;)    = false
     *  OAuth2Utils.isEmpty(&quot; bob &quot;)  = false
     * </pre>
     *
     * @param val
     *            string to evaluate as empty.
     * @return true if the string is empty else false.
     */
    public boolean isEmpty(String val) {
        return (val == null) ? true : "".equals(val) ? true : false;
    }

    /**
     * <pre>
     *      OAuth2Utils.isBlank(null)                = true
     *      OAuth2Utils.isBlank(&quot;&quot;)        = true
     *      OAuth2Utils.isBlank(&quot; &quot;)       = true
     *      OAuth2Utils.isBlank(&quot;bob&quot;)     = false
     *      OAuth2Utils.isBlank(&quot;  bob  &quot;) = false
     * </pre>
     */
    public boolean isBlank(String val) {
        return (val == null) ? true : isEmpty(val.trim());
    }

    public boolean isNotBlank(String val) {
        return !isBlank(val);
    }

    public static String joinStatic(Iterable<? extends Object> iterable, String delimiter) {
        if (null != iterable) {
            Iterator<? extends Object> iterator = iterable.iterator();
            if (!iterator.hasNext()) {
                return null;
            }
            StringBuilder buffer = new StringBuilder();
            buffer.append(iterator.next());
            String d = null != delimiter ? delimiter : SCOPE_DELIMITER;
            while (iterator.hasNext()) {
                buffer.append(d).append(iterator.next());
            }
            return buffer.toString();
        }
        return null;
    }


    public String join(Iterable<? extends Object> iterable, String delimiter) {
        return joinStatic(iterable, delimiter);
    }

    public Set<String> split(String string, String delimiter) {
        if (isNotBlank(string)) {
            StringTokenizer tokenizer =
                    new StringTokenizer(string, null != delimiter ? delimiter : SCOPE_DELIMITER);
            Set<String> result = new TreeSet<String>();
            while (tokenizer.hasMoreTokens()) {
                result.add(tokenizer.nextToken());
            }
            return Collections.unmodifiableSet(result);
        } else {
            return Collections.emptySet();
        }
    }

    /**
     * Given an OAuth2 request, attempts to pull out the confirmation key; this is optional.
     *
     * @param request
     *         OAuth2 request
     *
     * @return confirmation key represented as JSON, or null if not present
     */
    public JsonValue getConfirmationKey(OAuth2Request request) {
        String cnfKeyString = request.getParameter(ProofOfPossession.CNF_KEY);

        if (isBlank(cnfKeyString)) {
            return null;
        }

        return toJsonValue(Base64.decode(cnfKeyString));
    }

}
