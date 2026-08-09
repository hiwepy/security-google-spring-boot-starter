package org.springframework.security.boot.google.authentication;

import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GooglePublicKeysManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("GoogleAuthenticationProcessingFilter Tests")
class GoogleAuthenticationProcessingFilterTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        GoogleAuthenticationProcessingFilter instance = new GoogleAuthenticationProcessingFilter(new ObjectMapper());
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Default authorization param name is 'accessToken'")
    void testDefaultAuthParam() {
        GoogleAuthenticationProcessingFilter filter = new GoogleAuthenticationProcessingFilter(new ObjectMapper());
        assertThat(filter.getAuthorizationParamName()).isEqualTo("accessToken");
    }

    @Test
    @DisplayName("Authorization param name can be changed")
    void testSetAuthParam() {
        GoogleAuthenticationProcessingFilter filter = new GoogleAuthenticationProcessingFilter(new ObjectMapper());
        filter.setAuthorizationParamName("token");
        assertThat(filter.getAuthorizationParamName()).isEqualTo("token");
    }

    @Test
    @DisplayName("Public keys manager getter and setter")
    void testPublicKeysManager() {
        GoogleAuthenticationProcessingFilter filter = new GoogleAuthenticationProcessingFilter(new ObjectMapper());
        GooglePublicKeysManager mgr = mock(GooglePublicKeysManager.class);
        filter.setPublicKeysManager(mgr);
        assertThat(filter.getPublicKeysManager()).isSameAs(mgr);
    }

    @Test
    @DisplayName("Client IDs getter and setter")
    void testClientIds() {
        GoogleAuthenticationProcessingFilter filter = new GoogleAuthenticationProcessingFilter(new ObjectMapper());
        filter.setClientIds(Arrays.asList("id1", "id2"));
        assertThat(filter.getClientIds()).containsExactly("id1", "id2");
    }

    @Test
    @DisplayName("Clock getter and setter")
    void testClock() {
        GoogleAuthenticationProcessingFilter filter = new GoogleAuthenticationProcessingFilter(new ObjectMapper());
        assertThat(filter.getClock()).isNotNull();
    }

    @Test
    @DisplayName("Acceptable time skew seconds getter and setter")
    void testAcceptableTimeSkewSeconds() {
        GoogleAuthenticationProcessingFilter filter = new GoogleAuthenticationProcessingFilter(new ObjectMapper());
        filter.setAcceptableTimeSkewSeconds(60L);
        assertThat(filter.getAcceptableTimeSkewSeconds()).isEqualTo(60L);
    }

    @Test
    @DisplayName("AUTHORIZATION_PARAM constant")
    void testConstant() {
        assertThat(GoogleAuthenticationProcessingFilter.AUTHORIZATION_PARAM).isEqualTo("accessToken");
    }

    @Test
    @DisplayName("obtainAccessToken returns parameter from request")
    void testObtainAccessToken() {
        GoogleAuthenticationProcessingFilter filter = new GoogleAuthenticationProcessingFilter(new ObjectMapper());
        var request = new org.springframework.mock.web.MockHttpServletRequest();
        request.setParameter("accessToken", "my-token");
        assertThat(filter.obtainAccessToken(request)).isEqualTo("my-token");
    }
}
