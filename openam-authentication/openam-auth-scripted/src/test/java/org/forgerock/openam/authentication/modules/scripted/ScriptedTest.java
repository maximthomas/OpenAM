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
 * Copyright 2025 3A Systems LLC.
 */

package org.forgerock.openam.authentication.modules.scripted;

import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;
import com.iplanet.am.util.SystemProperties;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.service.AuthD;
import com.sun.identity.idm.AMIdentityRepository;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.scripting.ScriptEngineConfiguration;
import org.forgerock.openam.scripting.ScriptEvaluator;
import org.forgerock.openam.scripting.StandardScriptEngineManager;
import org.forgerock.openam.scripting.StandardScriptEvaluator;
import org.forgerock.openam.scripting.SupportedScriptingLanguage;
import org.forgerock.openam.scripting.service.ScriptConfiguration;
import org.forgerock.openam.scripting.service.ScriptingService;
import org.forgerock.openam.scripting.service.ScriptingServiceFactory;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.openam.scripting.ScriptConstants.ScriptContext.AUTHENTICATION_SERVER_SIDE;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@PrepareForTest({ SystemProperties.class, AuthD.class, InjectorHolder.class})
@PowerMockIgnore({"jdk.internal.reflect.*"})
public class ScriptedTest extends PowerMockTestCase {

    @Test
    public void testProcess() throws Exception {
        PowerMockito.mockStatic(SystemProperties.class);
        PowerMockito.suppress(PowerMockito.constructor(InjectorHolder.class));
        PowerMockito.mockStatic(InjectorHolder.class);
        PowerMockito.mockStatic(AuthD.class);

        ScriptingServiceFactory scriptingServiceFactory = mock(ScriptingServiceFactory.class);
        ScriptingService scriptingService = mock(ScriptingService.class);

        ScriptConfiguration scriptConfig = ScriptConfiguration.builder()
                .setId("test")
                .setName("test")
                .setScript("sharedState.put('test', 'test');\n" +
                        "sessionProperties.put('operation', requestData.getParameter('operation'));\n" +
                        "authState = SUCCESS")
                .setContext(AUTHENTICATION_SERVER_SIDE)
                .setLanguage(SupportedScriptingLanguage.JAVASCRIPT).build();

        when(scriptingService.get(anyString())).thenReturn(scriptConfig);
        when(scriptingServiceFactory.create(anyString())).thenReturn(scriptingService);
        PowerMockito.when(InjectorHolder.getInstance(Key.get(new TypeLiteral<ScriptingServiceFactory>() {}))).thenReturn(scriptingServiceFactory);

        StandardScriptEngineManager engineManager = new StandardScriptEngineManager();
        ScriptEngineConfiguration configuration = ScriptEngineConfiguration.builder()
                .withWhiteList(Arrays.asList(Pattern.compile(".*"))).build();
        engineManager.setConfiguration(configuration);

        ScriptEvaluator scriptEvaluator = new StandardScriptEvaluator(engineManager);

        PowerMockito.when(InjectorHolder.getInstance(Key.get(ScriptEvaluator.class, Names.named(AUTHENTICATION_SERVER_SIDE.name())))).thenReturn(scriptEvaluator);

        Scripted module = Mockito.spy(Scripted.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("operation")).thenReturn("test-operation");
        when(module.getHttpServletRequest()).thenReturn(request);
        doReturn(mock(AMIdentityRepository.class)).when(module).getAMIdentityRepository(anyString());

        doNothing().when(module).setUserSessionProperty(anyString(), anyString());

        Map<String, Object> sharedState = new HashMap<>();
                module.init(new Subject(), sharedState, new HashMap<String, Object>());

        HiddenValueCallback callback = new HiddenValueCallback("scripted value");

        module.process(new Callback[]{callback}, 2);

        assertThat(sharedState).contains(entry("test", "test"));
        verify(module, times(1))
                .setUserSessionProperty("operation", "test-operation");
    }
}