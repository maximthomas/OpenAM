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
 * Copyright 2023 3A Systems LLC
 */

package com.sun.identity.common.xml;

import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
public class XMLUtils {
    public static Element createDSctx(Document doc, String prefix, String namespace) {
        if (prefix == null || prefix.trim().length() == 0) {
            throw new IllegalArgumentException("You must supply a prefix");
        }
        Element ctx = doc.createElementNS(null, "namespaceContext");
        ctx.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:" + prefix.trim(), namespace);
        return ctx;
    }
}
