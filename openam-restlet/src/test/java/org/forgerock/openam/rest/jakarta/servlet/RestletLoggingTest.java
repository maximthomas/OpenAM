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

import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.ServiceLoader;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContainerInitializer;
import jakarta.servlet.ServletContext;

import org.restlet.Component;
import org.testng.annotations.Test;

public class RestletLoggingTest {

    @Test
    public void shouldPreserveLoggingWhenInitializingServlet() throws Exception {
        verifyLoggingInNewJvm("servlet");
    }

    @Test
    public void shouldPreserveLoggingBeforeApplicationListeners() throws Exception {
        verifyLoggingInNewJvm("container");
    }

    private void verifyLoggingInNewJvm(String startup) throws Exception {
        // Engine initialization and JUL configuration are global; each scenario must start with a fresh Engine.
        String classpath = String.join(File.pathSeparator, codeSource(LoggingProbe.class), codeSource(ServerServlet.class),
                codeSource(Component.class), codeSource(ServletContext.class));
        Process process = new ProcessBuilder(Paths.get(System.getProperty("java.home"), "bin", "java").toString(),
                "-ea", "-cp", classpath, LoggingProbe.class.getName(), startup)
                .redirectErrorStream(true).start();
        try {
            assertThat(process.waitFor(30, TimeUnit.SECONDS)).as("Logging probe completed").isTrue();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertThat(process.exitValue()).as("Logging probe output: %s", output).isZero();
        } finally {
            process.destroyForcibly();
        }
    }

    private String codeSource(Class<?> type) throws Exception {
        return Paths.get(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
    }

    public static class LoggingProbe {

        public static void main(String[] args) throws Exception {
            System.clearProperty("java.util.logging.config.file");
            System.clearProperty("java.util.logging.config.class");
            Logger root = Logger.getLogger("");
            for (Handler handler : root.getHandlers()) {
                root.removeHandler(handler);
            }
            TrackingHandler handler = new TrackingHandler();
            root.addHandler(handler);
            root.setLevel(Level.FINE);
            Logger applicationLogger = Logger.getLogger("openam.logging.probe");
            applicationLogger.setLevel(Level.FINEST);

            ServletContext context = (ServletContext) Proxy.newProxyInstance(LoggingProbe.class.getClassLoader(),
                    new Class<?>[] {ServletContext.class}, (proxy, method, values) -> {
                        switch (method.getName()) {
                        case "getInitParameterNames":
                        case "getAttributeNames":
                            return emptyEnumeration();
                        default:
                            return null;
                        }
                    });
            if ("container".equals(args[0])) {
                boolean initialized = false;
                for (ServletContainerInitializer initializer : ServiceLoader.load(ServletContainerInitializer.class)) {
                    if (initializer.getClass().getName().equals(
                            "org.forgerock.openam.rest.jakarta.servlet.RestletServletContainerInitializer")) {
                        initializer.onStartup(null, context);
                        initialized = true;
                    }
                }
                assert initialized : "Restlet container initializer is not registered";
                // A startup listener can create Restlet components before any servlet is instantiated.
                Component component = new Component();
                component.stop();
            } else {
                ServletConfig config = (ServletConfig) Proxy.newProxyInstance(LoggingProbe.class.getClassLoader(),
                        new Class<?>[] {ServletConfig.class}, (proxy, method, values) -> {
                            switch (method.getName()) {
                            case "getServletName":
                                return "loggingProbe";
                            case "getServletContext":
                                return context;
                            case "getInitParameterNames":
                                return emptyEnumeration();
                            default:
                                return null;
                            }
                        });
                ServerServlet servlet = new ServerServlet();
                try {
                    servlet.init(config);
                } finally {
                    servlet.destroy();
                }
            }

            assert Arrays.equals(root.getHandlers(), new Handler[] {handler}) : "Existing JUL handlers were replaced";
            assert root.getLevel() == Level.FINE : "Root JUL level changed";
            assert applicationLogger.getLevel() == Level.FINEST : "Application JUL level changed";
            assert !handler.closed : "Existing JUL handler was closed";
        }
    }

    private static class TrackingHandler extends Handler {

        private boolean closed;

        @Override
        public void publish(LogRecord record) {
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
            closed = true;
        }
    }
}
