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
 * Copyright 2026 3A Systems LLC.
 */
package org.forgerock.openam.oauth2.guice;

import static com.google.inject.name.Names.named;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.oauth2.core.AccessTokenVerifier.FORM_BODY;
import static org.forgerock.oauth2.core.AccessTokenVerifier.HEADER;
import static org.forgerock.oauth2.core.AccessTokenVerifier.QUERY_PARAM;
import static org.mockito.Mockito.mock;

import java.util.List;

import org.forgerock.oauth2.core.AccessTokenVerifier;
import org.forgerock.oauth2.core.TokenStore;
import org.openidentityplatform.openam.oauth2.core.FormBodyAccessTokenVerifier;
import org.openidentityplatform.openam.oauth2.core.HeaderAccessTokenVerifier;
import org.openidentityplatform.openam.oauth2.core.QueryParameterAccessTokenVerifier;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.google.inject.Binding;
import com.google.inject.Key;
import com.google.inject.spi.DefaultElementVisitor;
import com.google.inject.spi.Element;
import com.google.inject.spi.Elements;
import com.google.inject.spi.LinkedKeyBinding;

/**
 * Guards the seven {@link AccessTokenVerifier} binding sites in {@link OAuth2GuiceModule}.
 *
 * <p>A binding that points at the wrong class is invisible to the compiler and to the whole-reactor
 * build: it surfaces as a Guice {@code CreationException} when a server starts. These tests are the
 * only gate between such a mistake and a deployment.
 *
 * <p>The keys are asserted through the {@code Elements} SPI, which records the binding graph without
 * building an injector — so no dependency resolution, no SMS, and no eager singletons. The three
 * realm-agnostic providers are package-private {@code @Provides} methods, so they are simply called.
 */
public class OAuth2GuiceModuleTest {

    private List<Element> elements;

    @BeforeClass
    public void recordBindingGraph() {
        elements = Elements.getElements(new OAuth2GuiceModule());
    }

    /**
     * The unqualified key is the easiest of the seven to forget, and it is the one
     * {@code OpenIdConnectClientRegistrationService} injects.
     */
    @Test
    public void unqualifiedAccessTokenVerifierBindsToHeaderVerifier() {
        assertThat(linkedTargetOf(Key.get(AccessTokenVerifier.class)))
                .isEqualTo(HeaderAccessTokenVerifier.class);
    }

    @Test
    public void headerAccessTokenVerifierIsBound() {
        assertThat(linkedTargetOf(Key.get(AccessTokenVerifier.class, named(HEADER))))
                .isEqualTo(HeaderAccessTokenVerifier.class);
    }

    @Test
    public void formBodyAccessTokenVerifierIsBound() {
        assertThat(linkedTargetOf(Key.get(AccessTokenVerifier.class, named(FORM_BODY))))
                .isEqualTo(FormBodyAccessTokenVerifier.class);
    }

    @Test
    public void queryParamAccessTokenVerifierIsBound() {
        assertThat(linkedTargetOf(Key.get(AccessTokenVerifier.class, named(QUERY_PARAM))))
                .isEqualTo(QueryParameterAccessTokenVerifier.class);
    }

    @Test
    public void realmAgnosticHeaderProviderReturnsHeaderVerifier() {
        assertThat(new OAuth2GuiceModule().getRealmAgnosticHeaderAccessTokenVerifier(mock(TokenStore.class)))
                .isInstanceOf(HeaderAccessTokenVerifier.class);
    }

    @Test
    public void realmAgnosticFormBodyProviderReturnsFormBodyVerifier() {
        assertThat(new OAuth2GuiceModule().getRealmAgnosticFormBodyAccessTokenVerifier(mock(TokenStore.class)))
                .isInstanceOf(FormBodyAccessTokenVerifier.class);
    }

    @Test
    public void realmAgnosticQueryParamProviderReturnsQueryParameterVerifier() {
        assertThat(new OAuth2GuiceModule().getRealmAgnosticQueryParamAccessTokenVerifier(mock(TokenStore.class)))
                .isInstanceOf(QueryParameterAccessTokenVerifier.class);
    }

    /**
     * @return the implementation class the given key is linked to, or {@code null} if the key is
     * unbound or is not a {@code bind(...).to(...)} binding.
     */
    private Class<?> linkedTargetOf(final Key<?> key) {
        for (Element element : elements) {
            Class<?> target = element.acceptVisitor(new DefaultElementVisitor<Class<?>>() {
                @Override
                public <T> Class<?> visit(Binding<T> binding) {
                    if (binding.getKey().equals(key) && binding instanceof LinkedKeyBinding) {
                        return ((LinkedKeyBinding<?>) binding).getLinkedKey().getTypeLiteral().getRawType();
                    }
                    return null;
                }
            });
            if (target != null) {
                return target;
            }
        }
        return null;
    }
}
