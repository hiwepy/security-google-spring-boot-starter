/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {{ @link SecurityGoogleAutoConfiguration }}.
 *
 * <p>Verifies the auto-configuration activates under the expected conditions
 * and exposes its declared beans.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityGoogleAutoConfiguration Tests")
class SecurityGoogleAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner();

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        SecurityGoogleAutoConfiguration configuration = new SecurityGoogleAutoConfiguration();
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("transport() creates NetHttpTransport without proxy")
    void testTransportWithoutProxy() throws Exception {
        SecurityGoogleAutoConfiguration config = new SecurityGoogleAutoConfiguration();
        SecurityGoogleProperties props = new SecurityGoogleProperties();
        var transport = config.transport(props);
        assertThat(transport).isNotNull();
    }

    @Test
    @DisplayName("transport() creates NetHttpTransport with proxy")
    void testTransportWithProxy() throws Exception {
        SecurityGoogleAutoConfiguration config = new SecurityGoogleAutoConfiguration();
        SecurityGoogleProperties props = new SecurityGoogleProperties();
        props.setProxyHost("proxy.example.com");
        props.setProxyPort(8080);
        var transport = config.transport(props);
        assertThat(transport).isNotNull();
    }

    @Test
    @DisplayName("jsonFactory() creates GsonFactory")
    void testJsonFactory() {
        SecurityGoogleAutoConfiguration config = new SecurityGoogleAutoConfiguration();
        assertThat(config.jsonFactory()).isNotNull();
    }

    @Test
    @DisplayName("Auto-configuration loads when 'spring.security.google.enabled=true'")
    void testLoadsWhenEnabledPropertySet() {
        runner.withUserConfiguration(TestConfig.class, SecurityGoogleAutoConfiguration.class)
                .withPropertyValues("spring.security.google.enabled=true")
                .run(context -> assertThat(context).hasSingleBean(SecurityGoogleAutoConfiguration.class));
    }

    @Configuration
    static class TestConfig {
        @Bean
        public JwtPayloadRepository jwtPayloadRepository() {
            return mock(JwtPayloadRepository.class);
        }

        @Bean
        public UserDetailsServiceAdapter userDetailsServiceAdapter() {
            return new UserDetailsServiceAdapter() {
                @Override
                public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                    return mock(UserDetails.class);
                }
            };
        }
    }

    @Test
    @DisplayName("Auto-configuration is absent when property is not set")
    void testNotLoadedWhenPropertyAbsent() {
        runner.withUserConfiguration(SecurityGoogleAutoConfiguration.class)
                .run(context -> assertThat(context).doesNotHaveBean(SecurityGoogleAutoConfiguration.class));
    }
}
