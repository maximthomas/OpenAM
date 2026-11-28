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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.annotation.Resource;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.apache.catalina.startup.Tomcat;
import org.restlet.Component;
import org.testng.annotations.Test;

public class RestletLoggingTest {

    @Test
    public void shouldPreserveLoggingWhenInitializingServlet() throws Exception {
        String classpath = String.join(File.pathSeparator, codeSource(LoggingProbe.class), codeSource(ServerServlet.class),
                codeSource(Component.class), codeSource(ServletContext.class));
        verifyLoggingInNewJvm(classpath);
    }

    @Test
    public void shouldPreserveLoggingBeforeApplicationListeners() throws Exception {
        verifyContainerLogging("");
    }

    @Test
    public void shouldPreserveLoggingWithExplicitFragmentOrdering() throws Exception {
        verifyContainerLogging("<absolute-ordering><name>openam_restlet</name></absolute-ordering>");
    }

    private void verifyContainerLogging(String ordering) throws Exception {
        Path directory = Files.createTempDirectory("restlet-logging-");
        try {
            Path webInf = Files.createDirectories(directory.resolve("webapp/WEB-INF"));
            Path libs = Files.createDirectory(webInf.resolve("lib"));
            packageAdapter(Paths.get(codeSource(ServerServlet.class)), libs.resolve("openam-restlet.jar"));
            Path restletJar = Paths.get(codeSource(Component.class));
            Files.copy(restletJar, libs.resolve(restletJar.getFileName()));
            Files.writeString(webInf.resolve("web.xml"),
                    "<web-app version=\"3.0\" xmlns=\"http://java.sun.com/xml/ns/javaee\">"
                    + ordering + "<listener><listener-class>" + EarlyRestletListener.class.getName()
                    + "</listener-class></listener></web-app>");

            // Keep Restlet and its initializer off the parent classpath so Tomcat must discover the webapp JARs.
            String classpath = String.join(File.pathSeparator, codeSource(LoggingProbe.class), codeSource(Tomcat.class),
                    codeSource(Resource.class));
            verifyLoggingInNewJvm(classpath, directory.toString());
        } finally {
            List<Path> paths;
            try (Stream<Path> files = Files.walk(directory)) {
                paths = files.sorted(Comparator.reverseOrder()).collect(Collectors.toList());
            }
            for (Path path : paths) {
                Files.delete(path);
            }
        }
    }

    private void packageAdapter(Path classes, Path jar) throws Exception {
        try (Stream<Path> files = Files.walk(classes);
                JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            for (Path file : files.filter(Files::isRegularFile).collect(Collectors.toList())) {
                String name = classes.relativize(file).toString().replace(File.separatorChar, '/');
                output.putNextEntry(new JarEntry(name));
                Files.copy(file, output);
                output.closeEntry();
            }
        }
    }

    private void verifyLoggingInNewJvm(String classpath, String... arguments) throws Exception {
        // Engine initialization and JUL configuration are global; each scenario must start with a fresh Engine.
        List<String> command = new ArrayList<>(List.of(Paths.get(System.getProperty("java.home"), "bin", "java").toString(),
                "-ea", "-cp", classpath, LoggingProbe.class.getName()));
        command.addAll(Arrays.asList(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
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

            if (args.length == 0) {
                initializeServlet();
            } else {
                startContainer(Paths.get(args[0]));
            }

            assert Arrays.equals(root.getHandlers(), new Handler[] {handler}) : "Existing JUL handlers were replaced";
            assert root.getLevel() == Level.FINE : "Root JUL level changed";
            assert applicationLogger.getLevel() == Level.FINEST : "Application JUL level changed";
            assert !handler.closed : "Existing JUL handler was closed";
        }

        private static void initializeServlet() throws Exception {
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

        private static void startContainer(Path directory) throws Exception {
            Tomcat tomcat = new Tomcat();
            tomcat.setBaseDir(directory.resolve("tomcat").toString());
            tomcat.addWebapp("/openam", directory.resolve("webapp").toString());
            try {
                tomcat.start();
                assert EarlyRestletListener.initialized : "The application listener did not initialize Restlet";
            } finally {
                tomcat.stop();
                tomcat.destroy();
            }
        }
    }

    public static class EarlyRestletListener implements ServletContextListener {

        private static boolean initialized;

        @Override
        public void contextInitialized(ServletContextEvent event) {
            try {
                ClassLoader webapp = event.getServletContext().getClassLoader();
                webapp.loadClass("org.restlet.Component").getConstructor().newInstance();
                initialized = true;
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("The application listener could not initialize Restlet", e);
            }
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
