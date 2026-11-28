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
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;

import org.restlet.Application;
import org.restlet.Component;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class ServerServletConfigurationTest {

    private final Logger servletLogger = Logger.getLogger(ServerServlet.class.getName());
    private ServletContext context;
    private ServletConfig config;
    private ServerServlet servlet;
    private Handler logHandler;

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
        logHandler = mock(Handler.class);
        servletLogger.addHandler(logHandler);
    }

    @AfterMethod
    public void tearDown() {
        try {
            servlet.destroy();
        } finally {
            servletLogger.removeHandler(logHandler);
        }
    }

    @Test
    public void shouldCreateCustomComponentWithoutXmlConstructor() throws Exception {
        given(config.getInitParameter("org.restlet.component")).willReturn(CustomComponent.class.getName());

        servlet.init(config);

        assertThat(servlet.getComponent()).isInstanceOf(CustomComponent.class);
        verifyNoLegacyXmlWarning();
    }

    @Test
    public void shouldWarnWhenLegacyXmlHasNoReplacement() throws Exception {
        servlet.init(config);

        verify(logHandler).publish(argThat(record -> Level.WARNING.equals(record.getLevel())
                && record.getMessage().contains("WEB-INF/restlet.xml")
                && record.getMessage().contains("org.restlet.component")));
    }

    @Test
    public void shouldNotWarnWhenLegacyXmlIsAbsent() throws Exception {
        given(context.getResource("/WEB-INF/restlet.xml")).willReturn(null);

        servlet.init(config);

        verifyNoLegacyXmlWarning();
    }

    @Test
    public void shouldNotWarnWhenApplicationIsConfigured() throws Exception {
        given(config.getInitParameter("org.restlet.application")).willReturn(Application.class.getName());

        servlet.init(config);

        assertThat(servlet.getApplication()).isNotNull();
        verifyNoLegacyXmlWarning();
    }

    @Test
    public void shouldNotWarnWhenApplicationIsRegisteredInContext() throws Exception {
        Application application = new Application();
        given(context.getAttribute("org.restlet.ext.servlet.ServerServlet.application.configurationTest"))
                .willReturn(application);

        servlet.init(config);

        assertThat(servlet.getApplication()).isSameAs(application);
        verifyNoLegacyXmlWarning();
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
        verifyNoLegacyXmlWarning();
    }

    private void verifyNoLegacyXmlWarning() {
        verify(logHandler, never()).publish(argThat(record -> record.getMessage().contains("WEB-INF/restlet.xml")));
    }

    public static class CustomComponent extends Component {
    }
}
