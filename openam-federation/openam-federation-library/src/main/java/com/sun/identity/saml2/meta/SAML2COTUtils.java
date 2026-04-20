/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2006 Sun Microsystems Inc. All Rights Reserved
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
 * $Id: SAML2COTUtils.java,v 1.8 2009/10/28 23:58:58 exu Exp $
 *
 */


package com.sun.identity.saml2.meta;

import java.util.Iterator;
import java.util.List;

import com.sun.identity.saml2.jaxb.metadata.AttributeAuthorityDescriptorType;
import com.sun.identity.saml2.jaxb.metadata.AuthnAuthorityDescriptorType;
import com.sun.identity.saml2.jaxb.metadata.EntityDescriptorType;
import com.sun.identity.saml2.jaxb.metadata.IDPSSODescriptorType;
import com.sun.identity.saml2.jaxb.metadata.RoleDescriptorType;
import com.sun.identity.saml2.jaxb.metadata.SPSSODescriptorType;
import com.sun.identity.saml2.jaxb.metadata.XACMLAuthzDecisionQueryDescriptorType;
import com.sun.identity.saml2.jaxb.metadata.XACMLPDPDescriptorType;
import com.sun.identity.saml2.jaxb.metadataextquery.AttributeQueryDescriptorType;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.jaxb.entityconfig.AttributeType;
import com.sun.identity.saml2.jaxb.entityconfig.BaseConfigType;
import com.sun.identity.saml2.jaxb.entityconfig.ObjectFactory;
import com.sun.identity.saml2.jaxb.entityconfig.EntityConfigType;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;

import java.util.ArrayList;

/**
 * The <code>SAML2COTUtils</code> provides utility methods to update
 * the SAML2 Entity Configuration <code>cotlist</code> attributes
 * in the Service and Identity Provider configurations.
 */
public class SAML2COTUtils {
    
    private static Debug debug = SAML2MetaUtils.debug;
    private Object callerSession = null;    
    /**
     * Default Constructor.
     */
    public SAML2COTUtils()  {
    }
    
    /**
     * Constructor.
     * @param callerToken session token of the caller.
     */
    public SAML2COTUtils(Object callerToken) {
        callerSession = callerToken;
    }

    /**
     * Updates the entity config to add the circle of turst name to the
     * <code>cotlist</code> attribute. The Service Provider and Identity
     * Provider Configuration are updated.
     *
     * @param realm the realm name where the entity configuration is.
     * @param name the circle of trust name.
     * @param entityId the name of the Entity identifier.
     * @throws SAML2MetaException if there is a configuration error when
     *         updating the configuration.
     * @throws JAXBException is there is an error updating the entity
     *          configuration.
     */
    public void updateEntityConfig(String realm, String name, String entityId)
    throws SAML2MetaException, JAXBException {
        String classMethod = "SAML2COTUtils.updateEntityConfig: ";
        SAML2MetaManager metaManager = null;
        if (callerSession == null) {
            metaManager = new SAML2MetaManager();
        } else {
            metaManager = new SAML2MetaManager(callerSession);
        } 
        ObjectFactory objFactory = new ObjectFactory();
        // Check whether the entity id existed in the DS
        EntityDescriptorType edes = metaManager.getEntityDescriptor(
                realm, entityId);
        if (edes == null) {
            debug.error(classMethod +"No such entity: " + entityId);
            String[] data = {realm, entityId};
            throw new SAML2MetaException("entityid_invalid", data);
        }
        boolean isAffiliation = false;
        if (metaManager.getAffiliationDescriptor(realm, entityId) != null) {
            isAffiliation = true;
        }
        if (debug.messageEnabled()) {
            debug.message(classMethod + "is " + entityId + " in realm " 
                + realm + " an affiliation? " + isAffiliation);
        }

        EntityConfigType eConfig = metaManager.getEntityConfig(
            realm, entityId);
        if (eConfig == null) {
            BaseConfigType bctype = null;
            AttributeType atype = objFactory.createAttributeType();
            atype.setName(SAML2Constants.COT_LIST);
            atype.getValue().add(name);
            // add to eConfig
            EntityConfigType ele =objFactory.createEntityConfigType();
            ele.setEntityID(entityId);
            ele.setHosted(false);
            if (isAffiliation) {
                // handle affiliation case
                bctype = new BaseConfigType() {};
                bctype.getAttribute().add(atype);
                ele.setAffiliationConfig(bctype);
            } else {
                List<JAXBElement<BaseConfigType>> ll =
                    ele.getIDPSSOConfigOrSPSSOConfigOrAuthnAuthorityConfig();
                // Decide which role EntityDescriptorElement includes
                List<RoleDescriptorType> list =
                    edes.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor();

                for(Iterator<RoleDescriptorType> iter = list.iterator(); iter.hasNext();) {
                    Object obj = iter.next();
                    if (obj instanceof SPSSODescriptorType) {
                        bctype = new BaseConfigType() {};
                        bctype.getAttribute().add(atype);
                        ll.add(objFactory.createSPSSOConfig(bctype));
                    } else if (obj instanceof IDPSSODescriptorType) {
                        bctype = new BaseConfigType() {};
                        bctype.getAttribute().add(atype);
                        ll.add(objFactory.createIDPSSOConfig(bctype));
                    } else if (obj instanceof XACMLPDPDescriptorType) {
                        bctype = new BaseConfigType() {};
                        bctype.getAttribute().add(atype);
                        ll.add(objFactory.createXACMLPDPConfig(bctype));
                    } else if (obj instanceof
                            XACMLAuthzDecisionQueryDescriptorType)
                    {
                        bctype =  new BaseConfigType() {};
                        bctype.getAttribute().add(atype);
                        ll.add(objFactory.createXACMLAuthzDecisionQueryConfig(bctype));
                    } else if (obj instanceof AttributeAuthorityDescriptorType) {
                        bctype = new BaseConfigType() {};
                        bctype.getAttribute().add(atype);
                        ll.add(objFactory.createAttributeAuthorityConfig(bctype));
                    } else if (obj instanceof AttributeQueryDescriptorType){
                        bctype = new BaseConfigType() {};
                        bctype.getAttribute().add(atype);
                        ll.add(objFactory.createAttributeQueryConfig(bctype));
                    } else if (obj instanceof AuthnAuthorityDescriptorType) {
                        bctype = new BaseConfigType() {};
                        bctype.getAttribute().add(atype);
                        ll.add(objFactory.createAuthnAuthorityConfig(bctype));
                    }
                }
            }
            metaManager.setEntityConfig(realm,ele);
        } else {
            boolean needToSave = true;
            List elist = null; 
            if (isAffiliation) {
                BaseConfigType affiliationCfgElm = metaManager.getAffiliationConfig(realm, entityId);
                elist = new ArrayList();
                elist.add(affiliationCfgElm);
            } else {
                elist = eConfig.
                    getIDPSSOConfigOrSPSSOConfigOrAuthnAuthorityConfig();
            }
            for (Iterator iter = elist.iterator(); iter.hasNext();) {
                boolean foundCOT = false;
                BaseConfigType bConfig = (BaseConfigType)iter.next();
                List list = bConfig.getAttribute();
                for (Iterator iter2 = list.iterator(); iter2.hasNext();) {
                    AttributeType avp = (AttributeType)iter2.next();
                    if (avp.getName().trim().equalsIgnoreCase(
                            SAML2Constants.COT_LIST)) {
                        foundCOT = true;
                        List avpl = avp.getValue();
                        if (avpl.isEmpty() ||!containsValue(avpl,name)) {
                            avpl.add(name);
                            needToSave = true;
                            break;
                        }
                    }
                }
                // no cot_list in the original entity config
                if (!foundCOT) {
                    AttributeType atype = objFactory.createAttributeType();
                    atype.setName(SAML2Constants.COT_LIST);
                    atype.getValue().add(name);
                    list.add(atype);
                    needToSave = true;
                }
            }
            if (needToSave) {
                metaManager.setEntityConfig(realm,eConfig);
            }
        }
    }
    
    private boolean containsValue(List list, String name) {
        for (Iterator iter = list.iterator(); iter.hasNext();) {
            if (((String) iter.next()).trim().equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Removes the circle trust name passed from the <code>cotlist</code>
     * attribute in the Entity Config. The Service Provider and Identity
     * Provider Entity Configuration are updated.
     *
     * @param name the circle of trust name to be removed.
     * @param entityId the entity identifier of the provider.
     * @throws SAML2MetaException if there is an error updating the entity
     *          config.
     * @throws JAXBException if there is an error updating the entity config.
     */
    
    public void removeFromEntityConfig(String realm,String name,String entityId)
    throws SAML2MetaException, JAXBException {
        String classMethod = "SAML2COTUtils.removeFromEntityConfig: ";
        SAML2MetaManager metaManager = null;
        if (callerSession == null) {
            metaManager = new SAML2MetaManager();
        } else {
            metaManager = new SAML2MetaManager(callerSession);
        }
        // Check whether the entity id existed in the DS
        EntityDescriptorType edes = metaManager.getEntityDescriptor(
                realm, entityId);
        if (edes == null) {
            debug.error(classMethod +"No such entity: " + entityId);
            String[] data = {realm, entityId};
            throw new SAML2MetaException("entityid_invalid", data);
        }
        EntityConfigType eConfig = metaManager.getEntityConfig(
                realm, entityId);

        boolean isAffiliation = false;
        if (metaManager.getAffiliationDescriptor(realm, entityId) != null) {
            isAffiliation = true;
        }
        if (debug.messageEnabled()) {
            debug.message(classMethod + "is " + entityId + " in realm " 
                + realm + " an affiliation? " + isAffiliation);
        }

        if (eConfig != null) {
            List elist = null; 
            if (isAffiliation) {
                BaseConfigType affiliationCfgElm = metaManager.getAffiliationConfig(realm, entityId);
                elist = new ArrayList();
                elist.add(affiliationCfgElm);
            } else {
               elist = eConfig.
                    getIDPSSOConfigOrSPSSOConfigOrAuthnAuthorityConfig();
            }

            boolean needToSave = false;
            for (Iterator iter = elist.iterator(); iter.hasNext();) {
                BaseConfigType bConfig = (BaseConfigType)iter.next();
                List list = bConfig.getAttribute();
                for (Iterator iter2 = list.iterator(); iter2.hasNext();) {
                    AttributeType avp = (AttributeType)iter2.next();
                    if (avp.getName().trim().equalsIgnoreCase(
                            SAML2Constants.COT_LIST)) {
                        List avpl = avp.getValue();
                        if (avpl != null && !avpl.isEmpty() &&
                                containsValue(avpl,name)) {
                            avpl.remove(name);
                            needToSave = true;
                            break;
                        }
                    }
                }
            }
            if (needToSave) {
                metaManager.setEntityConfig(realm, eConfig);
            }
        }
    }
}
