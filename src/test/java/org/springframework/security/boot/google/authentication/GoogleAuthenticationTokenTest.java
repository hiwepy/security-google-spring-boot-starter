package org.springframework.security.boot.google.authentication;

import java.util.Collections;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("GoogleAuthenticationToken Tests")
class GoogleAuthenticationTokenTest {

    @Test
    @DisplayName("Unauthenticated token carries principal and access token")
    void testUnauthenticatedToken() {
        GoogleAuthenticationToken token = new GoogleAuthenticationToken("principal", "token");
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.getAccessToken()).isEqualTo("token");
        assertThat(token.getCredentials()).isEqualTo("token");
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("Authenticated token carries principal, access token and authorities")
    void testAuthenticatedToken() {
        GoogleAuthenticationToken token = new GoogleAuthenticationToken("user", "token",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        assertThat(token.getPrincipal()).isEqualTo("user");
        assertThat(token.getAccessToken()).isEqualTo("token");
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getAuthorities()).hasSize(1);
    }

    @Test
    @DisplayName("eraseCredentials nulls the access token")
    void testEraseCredentials() {
        GoogleAuthenticationToken token = new GoogleAuthenticationToken("p", "token");
        assertThat(token.getAccessToken()).isEqualTo("token");
        token.eraseCredentials();
        assertThat(token.getAccessToken()).isNull();
    }
}
