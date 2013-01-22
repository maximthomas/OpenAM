//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v1.0.6-b27-fcs 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2012.06.11 at 10:34:07 AM PDT 
//


package com.sun.identity.saml2.jaxb.metadata;


/**
 * Java content class for EntitiesDescriptorType complex type.
 * <p>The following schema fragment specifies the expected content contained within this java content object. (defined at file:/Users/allan/A-SVN/trunk/opensso/products/federation/library/xsd/saml2/saml-schema-metadata-2.0.xsd line 113)
 * <p>
 * <pre>
 * &lt;complexType name="EntitiesDescriptorType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2000/09/xmldsig#}Signature" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}Extensions" minOccurs="0"/>
 *         &lt;choice maxOccurs="unbounded">
 *           &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor"/>
 *           &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor"/>
 *         &lt;/choice>
 *       &lt;/sequence>
 *       &lt;attribute name="ID" type="{http://www.w3.org/2001/XMLSchema}ID" />
 *       &lt;attribute name="Name" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="cacheDuration" type="{http://www.w3.org/2001/XMLSchema}duration" />
 *       &lt;attribute name="validUntil" type="{http://www.w3.org/2001/XMLSchema}dateTime" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 */
public interface EntitiesDescriptorType {


    /**
     * Gets the value of the extensions property.
     * 
     * @return
     *     possible object is
     *     {@link com.sun.identity.saml2.jaxb.metadata.ExtensionsType}
     *     {@link com.sun.identity.saml2.jaxb.metadata.ExtensionsElement}
     */
    com.sun.identity.saml2.jaxb.metadata.ExtensionsType getExtensions();

    /**
     * Sets the value of the extensions property.
     * 
     * @param value
     *     allowed object is
     *     {@link com.sun.identity.saml2.jaxb.metadata.ExtensionsType}
     *     {@link com.sun.identity.saml2.jaxb.metadata.ExtensionsElement}
     */
    void setExtensions(com.sun.identity.saml2.jaxb.metadata.ExtensionsType value);

    /**
     * Gets the value of the name property.
     * 
     * @return
     *     possible object is
     *     {@link java.lang.String}
     */
    java.lang.String getName();

    /**
     * Sets the value of the name property.
     * 
     * @param value
     *     allowed object is
     *     {@link java.lang.String}
     */
    void setName(java.lang.String value);

    /**
     * Gets the value of the validUntil property.
     * 
     * @return
     *     possible object is
     *     {@link java.util.Calendar}
     */
    java.util.Calendar getValidUntil();

    /**
     * Sets the value of the validUntil property.
     * 
     * @param value
     *     allowed object is
     *     {@link java.util.Calendar}
     */
    void setValidUntil(java.util.Calendar value);

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link java.lang.String}
     */
    java.lang.String getID();

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link java.lang.String}
     */
    void setID(java.lang.String value);

    /**
     * Gets the value of the cacheDuration property.
     * 
     * @return
     *     possible object is
     *     {@link java.lang.String}
     */
    java.lang.String getCacheDuration();

    /**
     * Sets the value of the cacheDuration property.
     * 
     * @param value
     *     allowed object is
     *     {@link java.lang.String}
     */
    void setCacheDuration(java.lang.String value);

    /**
     * Gets the value of the EntityDescriptorOrEntitiesDescriptor property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the EntityDescriptorOrEntitiesDescriptor property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getEntityDescriptorOrEntitiesDescriptor().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link com.sun.identity.saml2.jaxb.metadata.EntitiesDescriptorElement}
     * {@link com.sun.identity.saml2.jaxb.metadata.EntityDescriptorElement}
     * 
     */
    java.util.List getEntityDescriptorOrEntitiesDescriptor();

    /**
     * Gets the value of the signature property.
     * 
     * @return
     *     possible object is
     *     {@link com.sun.identity.saml2.jaxb.xmlsig.SignatureType}
     *     {@link com.sun.identity.saml2.jaxb.xmlsig.SignatureElement}
     */
    com.sun.identity.saml2.jaxb.xmlsig.SignatureType getSignature();

    /**
     * Sets the value of the signature property.
     * 
     * @param value
     *     allowed object is
     *     {@link com.sun.identity.saml2.jaxb.xmlsig.SignatureType}
     *     {@link com.sun.identity.saml2.jaxb.xmlsig.SignatureElement}
     */
    void setSignature(com.sun.identity.saml2.jaxb.xmlsig.SignatureType value);

}
