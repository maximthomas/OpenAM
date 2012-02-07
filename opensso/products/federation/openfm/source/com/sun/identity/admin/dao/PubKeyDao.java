/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2009 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * $Id: PubKeyDao.java,v 1.1 2009/12/08 02:02:30 babysunil Exp $
 */

package com.sun.identity.admin.dao;

import com.sun.identity.saml2.jaxb.entityconfig.BaseConfigType;
import com.sun.identity.saml2.jaxb.entityconfig.EntityConfigElement;
import com.sun.identity.saml2.jaxb.entityconfig.IDPSSOConfigElement;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.saml2.meta.SAML2MetaSecurityUtils;
import com.sun.identity.saml2.meta.SAML2MetaUtils;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class PubKeyDao implements Serializable {
    
    public String getPublicKeyContent(String realm, String entityId) {
        try {
            SAML2MetaManager samlManager = new SAML2MetaManager();
            Map extValueMap = new HashMap();
            IDPSSOConfigElement idpssoConfig = samlManager.getIDPSSOConfig(realm, entityId);
            if (idpssoConfig != null) {
                BaseConfigType baseConfig = (BaseConfigType) idpssoConfig;
                extValueMap = SAML2MetaUtils.getAttributes(baseConfig);
            }
            
            List aList = (List) extValueMap.get("signingCertAlias");
            String signingCertAlias = null;
            if (aList != null) {
                signingCertAlias = (String) aList.get(0);
            }
            String publickey =
                    SAML2MetaSecurityUtils.buildX509Certificate(signingCertAlias);
            String pubKey = 
                    "-----BEGIN CERTIFICATE-----\n" + publickey + "-----END CERTIFICATE-----\n";
            return pubKey;
            
        } catch (SAML2MetaException e) {
            throw new RuntimeException(e);
        }
    }
}
