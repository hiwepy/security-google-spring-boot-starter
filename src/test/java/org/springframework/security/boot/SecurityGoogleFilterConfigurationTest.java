package org.springframework.security.boot;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.google.authentication.GoogleAuthenticationProcessingFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.util.Clock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("SecurityGoogleFilterConfiguration Tests")
class SecurityGoogleFilterConfigurationTest {

    @Test
    @DisplayName("Filter configuration class can be instantiated")
    void testInstantiation() {
        SecurityGoogleFilterConfiguration instance = new SecurityGoogleFilterConfiguration();
        assertThat(instance).isNotNull();
    }

    @SuppressWarnings("unchecked")
    @Test
    @DisplayName("Inner GoogleWebSecurityCustomizerAdapter can be instantiated")
    void testInnerClassInstantiation() {
        SecurityBizProperties bizProperties = new SecurityBizProperties();
        SecurityGoogleAuthcProperties authc = new SecurityGoogleAuthcProperties();
        SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();

        ObjectProvider emptyProvider = mock(ObjectProvider.class);
        when(emptyProvider.getIfAvailable()).thenReturn(null);

        ObjectProvider listProvider = mock(ObjectProvider.class);
        when(listProvider.stream()).thenAnswer(inv -> Stream.empty());

        ObjectProvider clockProvider = mock(ObjectProvider.class);
        when(clockProvider.getIfAvailable(org.mockito.ArgumentMatchers.any())).thenReturn(Clock.SYSTEM);

        ObjectProvider objectMapperProvider = mock(ObjectProvider.class);
        when(objectMapperProvider.getIfAvailable()).thenReturn(new ObjectMapper());

        ObjectProvider pkmProvider = mock(ObjectProvider.class);
        when(pkmProvider.getIfAvailable()).thenReturn(null);

        var adapter = new SecurityGoogleFilterConfiguration.GoogleWebSecurityCustomizerAdapter(
                bizProperties, authc, sessionMgt,
                pkmProvider,
                clockProvider,
                listProvider,
                emptyProvider,
                listProvider,
                listProvider,
                listProvider,
                listProvider,
                listProvider,
                objectMapperProvider,
                emptyProvider,
                emptyProvider
        );
        assertThat(adapter).isNotNull();
    }

    @SuppressWarnings("unchecked")
    @Test
    @DisplayName("authenticationProcessingFilter() creates configured filter")
    void testAuthenticationProcessingFilter() throws Exception {
        SecurityBizProperties bizProperties = new SecurityBizProperties();
        SecurityGoogleAuthcProperties authc = new SecurityGoogleAuthcProperties();
        SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();

        ObjectProvider emptyProvider = mock(ObjectProvider.class);
        when(emptyProvider.getIfAvailable()).thenReturn(null);

        // Provide a non-empty auth provider stream so authenticationManagerBean() can build a manager
        AuthenticationProvider authProvider = mock(AuthenticationProvider.class);
        when(authProvider.supports(org.mockito.ArgumentMatchers.any())).thenReturn(true);
        ObjectProvider authProviderProv = mock(ObjectProvider.class);
        when(authProviderProv.stream()).thenAnswer(inv -> Stream.of(authProvider));

        ObjectProvider listProvider = mock(ObjectProvider.class);
        when(listProvider.stream()).thenAnswer(inv -> Stream.empty());

        ObjectProvider clockProvider = mock(ObjectProvider.class);
        when(clockProvider.getIfAvailable(org.mockito.ArgumentMatchers.any())).thenReturn(Clock.SYSTEM);

        ObjectProvider objectMapperProvider = mock(ObjectProvider.class);
        when(objectMapperProvider.getIfAvailable()).thenReturn(new ObjectMapper());

        ObjectProvider pkmProvider = mock(ObjectProvider.class);
        when(pkmProvider.getIfAvailable()).thenReturn(null);

        var adapter = new SecurityGoogleFilterConfiguration.GoogleWebSecurityCustomizerAdapter(
                bizProperties, authc, sessionMgt,
                pkmProvider, clockProvider,
                listProvider, emptyProvider,
                authProviderProv, listProvider, listProvider, listProvider, listProvider,
                objectMapperProvider, emptyProvider, emptyProvider
        );

        GoogleAuthenticationProcessingFilter filter = adapter.authenticationProcessingFilter();
        assertThat(filter).isNotNull();
        assertThat(filter.getAuthorizationParamName()).isEqualTo("accessToken");
    }

    @SuppressWarnings("unchecked")
    @Test
    @DisplayName("googleSecurityFilterChain configures HttpSecurity")
    void testGoogleSecurityFilterChain() throws Exception {
        SecurityBizProperties bizProperties = new SecurityBizProperties();
        SecurityGoogleAuthcProperties authc = new SecurityGoogleAuthcProperties();
        SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();

        ObjectProvider emptyProvider = mock(ObjectProvider.class);
        when(emptyProvider.getIfAvailable()).thenReturn(null);

        AuthenticationProvider authProvider = mock(AuthenticationProvider.class);
        when(authProvider.supports(any())).thenReturn(true);
        ObjectProvider authProviderProv = mock(ObjectProvider.class);
        when(authProviderProv.stream()).thenAnswer(inv -> Stream.of(authProvider));

        ObjectProvider listProvider = mock(ObjectProvider.class);
        when(listProvider.stream()).thenAnswer(inv -> Stream.empty());

        ObjectProvider clockProvider = mock(ObjectProvider.class);
        when(clockProvider.getIfAvailable(any())).thenReturn(Clock.SYSTEM);

        ObjectProvider objectMapperProvider = mock(ObjectProvider.class);
        when(objectMapperProvider.getIfAvailable()).thenReturn(new ObjectMapper());

        ObjectProvider pkmProvider = mock(ObjectProvider.class);
        when(pkmProvider.getIfAvailable()).thenReturn(null);

        var adapter = new SecurityGoogleFilterConfiguration.GoogleWebSecurityCustomizerAdapter(
                bizProperties, authc, sessionMgt,
                pkmProvider, clockProvider,
                listProvider, emptyProvider,
                authProviderProv, listProvider, listProvider, listProvider, listProvider,
                objectMapperProvider, emptyProvider, emptyProvider
        );

        HttpSecurity http = mock(HttpSecurity.class, RETURNS_SELF);
        when(http.build()).thenReturn(mock(DefaultSecurityFilterChain.class));

        var chain = adapter.googleSecurityFilterChain(http);
        assertThat(chain).isNotNull();
    }
}
