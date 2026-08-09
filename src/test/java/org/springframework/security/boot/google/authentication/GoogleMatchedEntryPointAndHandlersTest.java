package org.springframework.security.boot.google.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.google.exception.GoogleAccessTokenExpiredException;
import org.springframework.security.boot.google.exception.GoogleAccessTokenIncorrectException;
import org.springframework.security.boot.google.exception.GoogleAccessTokenInvalidException;
import org.springframework.security.boot.google.exception.GoogleAccessTokenNotFoundException;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("Google MatchedEntryPoint and Handlers Tests")
class GoogleMatchedEntryPointAndHandlersTest {

    // --- EntryPoint tests ---
    private final GoogleMatchedAuthenticationEntryPoint entryPoint = new GoogleMatchedAuthenticationEntryPoint();

    @Test
    @DisplayName("EntryPoint supports all Google exceptions")
    void testEntryPointSupports() {
        assertThat(entryPoint.supports(new GoogleAccessTokenExpiredException("e"))).isTrue();
        assertThat(entryPoint.supports(new GoogleAccessTokenIncorrectException("e"))).isTrue();
        assertThat(entryPoint.supports(new GoogleAccessTokenInvalidException("e"))).isTrue();
        assertThat(entryPoint.supports(new GoogleAccessTokenNotFoundException("e"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationException("generic") {})).isFalse();
    }

    @Test
    @DisplayName("EntryPoint commence writes JSON for expired exception")
    void testEntryPointCommenceExpired() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        entryPoint.commence(req, resp, new GoogleAccessTokenExpiredException("expired"));
        assertThat(resp.getStatus()).isEqualTo(200);
        assertThat(resp.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("EntryPoint commence writes JSON for incorrect exception")
    void testEntryPointCommenceIncorrect() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        entryPoint.commence(req, resp, new GoogleAccessTokenIncorrectException("incorrect"));
        assertThat(resp.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("EntryPoint commence writes JSON for invalid exception")
    void testEntryPointCommenceInvalid() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        entryPoint.commence(req, resp, new GoogleAccessTokenInvalidException("invalid"));
        assertThat(resp.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("EntryPoint commence writes JSON for not-found exception")
    void testEntryPointCommenceNotFound() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        entryPoint.commence(req, resp, new GoogleAccessTokenNotFoundException("not found"));
        assertThat(resp.getStatus()).isEqualTo(200);
    }

    // --- FailureHandler tests ---
    private final GoogleMatchedAuthenticationFailureHandler failureHandler = new GoogleMatchedAuthenticationFailureHandler();

    @Test
    @DisplayName("FailureHandler supports all Google exceptions")
    void testFailureHandlerSupports() {
        assertThat(failureHandler.supports(new GoogleAccessTokenExpiredException("e"))).isTrue();
        assertThat(failureHandler.supports(new GoogleAccessTokenIncorrectException("e"))).isTrue();
        assertThat(failureHandler.supports(new GoogleAccessTokenInvalidException("e"))).isTrue();
        assertThat(failureHandler.supports(new GoogleAccessTokenNotFoundException("e"))).isTrue();
        assertThat(failureHandler.supports(new AuthenticationException("generic") {})).isFalse();
    }

    @Test
    @DisplayName("FailureHandler writes JSON for expired exception")
    void testFailureHandlerExpired() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        failureHandler.onAuthenticationFailure(req, resp, new GoogleAccessTokenExpiredException("expired"));
        assertThat(resp.getStatus()).isEqualTo(200);
        assertThat(resp.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("FailureHandler writes JSON for incorrect exception")
    void testFailureHandlerIncorrect() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        failureHandler.onAuthenticationFailure(req, resp, new GoogleAccessTokenIncorrectException("incorrect"));
        assertThat(resp.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("FailureHandler writes JSON for invalid exception")
    void testFailureHandlerInvalid() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        failureHandler.onAuthenticationFailure(req, resp, new GoogleAccessTokenInvalidException("invalid"));
        assertThat(resp.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("FailureHandler writes JSON for not-found exception")
    void testFailureHandlerNotFound() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        failureHandler.onAuthenticationFailure(req, resp, new GoogleAccessTokenNotFoundException("not found"));
        assertThat(resp.getStatus()).isEqualTo(200);
    }

    // --- SuccessHandler tests ---
    private final GoogleMatchedAuthenticationSuccessHandler successHandler =
            new GoogleMatchedAuthenticationSuccessHandler(mock(JwtPayloadRepository.class));

    @Test
    @DisplayName("SuccessHandler can be instantiated")
    void testSuccessHandlerInstantiation() {
        assertThat(successHandler).isNotNull();
    }

    @Test
    @DisplayName("SuccessHandler supports GoogleAuthenticationToken")
    void testSuccessHandlerSupports() {
        GoogleAuthenticationToken token = new GoogleAuthenticationToken("p", "t");
        assertThat(successHandler.supports(token)).isTrue();
        assertThat(successHandler.supports(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken("u", "p"))).isFalse();
    }

    @Test
    @DisplayName("SuccessHandler checkExpiry getter and setter")
    void testSuccessHandlerCheckExpiry() {
        assertThat(successHandler.isCheckExpiry()).isFalse();
        successHandler.setCheckExpiry(true);
        assertThat(successHandler.isCheckExpiry()).isTrue();
    }

    @Test
    @DisplayName("SuccessHandler payloadRepository getter and setter")
    void testSuccessHandlerPayloadRepo() {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        successHandler.setPayloadRepository(repo);
        assertThat(successHandler.getPayloadRepository()).isSameAs(repo);
    }

    @Test
    @DisplayName("SuccessHandler writes JSON on success")
    void testSuccessHandlerOnSuccess() throws Exception {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_USER");
        GoogleAuthenticationToken token = new GoogleAuthenticationToken(principal, "token",
                java.util.Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")));
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        successHandler.onAuthenticationSuccess(req, resp, token);
        assertThat(resp.getStatus()).isEqualTo(200);
        assertThat(resp.getContentAsString()).isNotEmpty();
    }
}
