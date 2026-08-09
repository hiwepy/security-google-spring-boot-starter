package org.springframework.security.boot.google.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("GoogleLoginRequest Tests")
class GoogleLoginRequestTest {

    @Test
    @DisplayName("Constructor sets access token")
    void testConstructor() {
        GoogleLoginRequest request = new GoogleLoginRequest("token123");
        assertThat(request.getAccessToken()).isEqualTo("token123");
    }

    @Test
    @DisplayName("Setter and getter work correctly")
    void testSetGet() {
        GoogleLoginRequest request = new GoogleLoginRequest("old");
        request.setAccessToken("new");
        assertThat(request.getAccessToken()).isEqualTo("new");
    }
}
