package org.springframework.security.boot.google.authentication;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("GoogleAuthenticationProvider Tests")
class GoogleAuthenticationProviderTest {

    private UserDetailsServiceAdapter userDetailsService;
    private GoogleAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        userDetailsService = mock(UserDetailsServiceAdapter.class);
        provider = new GoogleAuthenticationProvider(userDetailsService);
    }

    @Test
    @DisplayName("Constructor stores dependencies")
    void testConstructor() {
        assertThat(provider.getUserDetailsService()).isSameAs(userDetailsService);
        assertThat(provider.getUserDetailsChecker()).isNotNull();
    }

    @Test
    @DisplayName("supports returns true for GoogleAuthenticationToken")
    void testSupports() {
        assertThat(provider.supports(GoogleAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(Object.class)).isFalse();
    }

    @Test
    @DisplayName("setUserDetailsChecker replaces the default checker")
    void testSetUserDetailsChecker() {
        var checker = mock(org.springframework.security.core.userdetails.UserDetailsChecker.class);
        provider.setUserDetailsChecker(checker);
        assertThat(provider.getUserDetailsChecker()).isSameAs(checker);
    }

    @Test
    @DisplayName("authenticate throws on null authentication")
    void testAuthenticateNull() {
        assertThatThrownBy(() -> provider.authenticate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("authenticate returns authenticated token for SecurityPrincipal")
    void testAuthenticateWithSecurityPrincipal() {
        GoogleAuthenticationToken token = new GoogleAuthenticationToken("google-user", "access-token");
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));

        SecurityPrincipal principal = mock(SecurityPrincipal.class);
        when(principal.isEnabled()).thenReturn(true);
        when(principal.isAccountNonExpired()).thenReturn(true);
        when(principal.isCredentialsNonExpired()).thenReturn(true);
        when(principal.isAccountNonLocked()).thenReturn(true);
        doReturn(authorities).when(principal).getAuthorities();
        doReturn(principal).when(userDetailsService).loadUserDetails(any(Authentication.class));

        var result = provider.authenticate(token);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
    }

    @Test
    @DisplayName("authenticate returns authenticated token for plain UserDetails")
    void testAuthenticateWithPlainUserDetails() {
        GoogleAuthenticationToken token = new GoogleAuthenticationToken("google-user", "access-token");
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));

        UserDetails ud = mock(UserDetails.class);
        when(ud.getUsername()).thenReturn("user");
        when(ud.getPassword()).thenReturn("pass");
        when(ud.isEnabled()).thenReturn(true);
        when(ud.isAccountNonExpired()).thenReturn(true);
        when(ud.isCredentialsNonExpired()).thenReturn(true);
        when(ud.isAccountNonLocked()).thenReturn(true);
        doReturn(authorities).when(ud).getAuthorities();
        doReturn(ud).when(userDetailsService).loadUserDetails(any(Authentication.class));

        var result = provider.authenticate(token);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isEqualTo("google-user");
    }

    @Test
    @DisplayName("authenticate sets details from original token")
    void testAuthenticateSetsDetails() {
        GoogleAuthenticationToken token = new GoogleAuthenticationToken("google-user", "access-token");
        token.setDetails("some-detail");

        UserDetails ud = mock(UserDetails.class);
        when(ud.getUsername()).thenReturn("user");
        when(ud.isEnabled()).thenReturn(true);
        when(ud.isAccountNonExpired()).thenReturn(true);
        when(ud.isCredentialsNonExpired()).thenReturn(true);
        when(ud.isAccountNonLocked()).thenReturn(true);
        doReturn(Collections.emptyList()).when(ud).getAuthorities();
        doReturn(ud).when(userDetailsService).loadUserDetails(any(Authentication.class));

        var result = provider.authenticate(token);
        assertThat(result.getDetails()).isEqualTo("some-detail");
    }
}
