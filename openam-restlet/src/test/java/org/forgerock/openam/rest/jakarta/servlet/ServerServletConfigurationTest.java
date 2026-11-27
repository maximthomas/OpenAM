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
 * Copyright 2026 3A Systems, LLC.
 */
package org.forgerock.openam.rest.jakarta.servlet;

import static java.util.Collections.emptyEnumeration;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;

import org.restlet.Application;
import org.restlet.Component;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class ServerServletConfigurationTest {

    private ServletContext context;
    private ServletConfig config;
    private ServerServlet servlet;

    @BeforeMethod
    public void setUp() throws Exception {
        context = mock(ServletContext.class);
        given(context.getInitParameterNames()).willReturn(emptyEnumeration());
        given(context.getAttributeNames()).willReturn(emptyEnumeration());
        given(context.getResource("/WEB-INF/restlet.xml")).willReturn(
                getClass().getResource("/restlet-component.xml"));
        config = mock(ServletConfig.class);
        given(config.getServletName()).willReturn("configurationTest");
        given(config.getServletContext()).willReturn(context);
        given(config.getInitParameterNames()).willReturn(emptyEnumeration());
        servlet = new ServerServlet();
    }

    @AfterMethod
    public void tearDown() {
        servlet.destroy();
    }

    @Test
    public void shouldCreateCustomComponentWithoutXmlConstructor() throws Exception {
        given(config.getInitParameter("org.restlet.component")).willReturn(CustomComponent.class.getName());

        servlet.init(config);

        assertThat(servlet.getComponent()).isInstanceOf(CustomComponent.class);
    }

    @Test
    public void shouldCreateApplicationWithExistingComponentAndLegacyXml() throws Exception {
        Component component = new Component();
        given(context.getAttribute("org.restlet.ext.servlet.ServerServlet.component.configurationTest"))
                .willReturn(component);
        given(config.getInitParameter("org.restlet.application")).willReturn(Application.class.getName());

        servlet.init(config);

        assertThat(servlet.getApplication()).isNotNull();
        assertThat(servlet.getComponent()).isSameAs(component);
    }

    public static class CustomComponent extends Component {
    }
}
