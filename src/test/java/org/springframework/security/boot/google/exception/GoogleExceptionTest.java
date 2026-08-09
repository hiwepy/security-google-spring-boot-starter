package org.springframework.security.boot.google.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Google Exception Classes Tests")
class GoogleExceptionTest {

    @Test
    @DisplayName("GoogleAccessTokenNotFoundException constructor with message")
    void testNotFoundException() {
        var ex = new GoogleAccessTokenNotFoundException("not found");
        assertThat(ex.getMessage()).isEqualTo("not found");
        assertThat(ex.getCause()).isNull();
    }

    @Test
    @DisplayName("GoogleAccessTokenNotFoundException constructor with message and cause")
    void testNotFoundExceptionWithCause() {
        var cause = new RuntimeException("root");
        var ex = new GoogleAccessTokenNotFoundException("not found", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("GoogleAccessTokenExpiredException constructor with message")
    void testExpiredException() {
        var ex = new GoogleAccessTokenExpiredException("expired");
        assertThat(ex.getMessage()).isEqualTo("expired");
    }

    @Test
    @DisplayName("GoogleAccessTokenExpiredException constructor with message and cause")
    void testExpiredExceptionWithCause() {
        var cause = new RuntimeException("root");
        var ex = new GoogleAccessTokenExpiredException("expired", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("GoogleAccessTokenInvalidException constructor with message")
    void testInvalidException() {
        var ex = new GoogleAccessTokenInvalidException("invalid");
        assertThat(ex.getMessage()).isEqualTo("invalid");
    }

    @Test
    @DisplayName("GoogleAccessTokenInvalidException constructor with message and cause")
    void testInvalidExceptionWithCause() {
        var cause = new RuntimeException("root");
        var ex = new GoogleAccessTokenInvalidException("invalid", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("GoogleAccessTokenIncorrectException constructor with message")
    void testIncorrectException() {
        var ex = new GoogleAccessTokenIncorrectException("incorrect");
        assertThat(ex.getMessage()).isEqualTo("incorrect");
    }

    @Test
    @DisplayName("GoogleAccessTokenIncorrectException constructor with message and cause")
    void testIncorrectExceptionWithCause() {
        var cause = new RuntimeException("root");
        var ex = new GoogleAccessTokenIncorrectException("incorrect", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }
}
