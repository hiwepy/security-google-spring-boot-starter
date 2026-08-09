package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SecurityGoogleProperties Tests")
class SecurityGooglePropertiesTest {

    @Test
    @DisplayName("Default values are correct")
    void testDefaults() {
        SecurityGoogleProperties props = new SecurityGoogleProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.getPublicCertsEncodedUrl()).isNotEmpty();
        assertThat(props.getProxyHost()).isNull();
        assertThat(props.getProxyPort()).isEqualTo(0);
    }

    @Test
    @DisplayName("Getters and setters work correctly")
    void testGettersSetters() {
        SecurityGoogleProperties props = new SecurityGoogleProperties();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();

        props.setPublicCertsEncodedUrl("https://example.com/certs");
        assertThat(props.getPublicCertsEncodedUrl()).isEqualTo("https://example.com/certs");

        props.setProxyHost("proxy.example.com");
        assertThat(props.getProxyHost()).isEqualTo("proxy.example.com");

        props.setProxyPort(8080);
        assertThat(props.getProxyPort()).isEqualTo(8080);
    }

    @Test
    @DisplayName("PREFIX constant has expected value")
    void testPREFIXConstant() {
        assertThat(SecurityGoogleProperties.PREFIX).isEqualTo("spring.security.google");
    }
}
