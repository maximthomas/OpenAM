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
 * Portions copyright 2026 3A Systems LLC.
 */

package org.forgerock.guice.core;

/**
 * Lets a test outside this package reset {@link InjectorConfiguration}'s process-global
 * {@link GuiceModuleLoader} to the framework default.
 *
 * <p>A {@link GuiceTestCase} that swaps in an empty loader (so {@code super.setupGuiceModules()} does not
 * service-load every real module) cannot undo it from its own package: the default loader's constructor is
 * package-private here. {@link GuiceTestCase#teardownGuiceModules()} restores only the {@code InjectorHolder},
 * not the loader, so without this shim the empty loader leaks to later tests in the same fork.
 */
public final class GuiceModuleLoaderAccessor {

    private GuiceModuleLoaderAccessor() {
    }

    /** Resets the loader to a fresh {@link GuiceModuleServiceLoader} — the value {@code InjectorConfiguration} starts with. */
    public static void restoreDefault() {
        InjectorConfiguration.setGuiceModuleLoader(new GuiceModuleServiceLoader(new ServiceLoaderWrapper()));
    }
}
