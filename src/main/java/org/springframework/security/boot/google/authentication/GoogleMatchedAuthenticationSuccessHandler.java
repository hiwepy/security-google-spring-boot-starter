package org.springframework.security.boot.google.authentication;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Authentication success handler for Google authentication.
 * <p>Writes the authenticated user profile payload as a JSON response to the client
 * upon successful Google ID token authentication.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class GoogleMatchedAuthenticationSuccessHandler implements MatchedAuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private JwtPayloadRepository payloadRepository;
	private boolean checkExpiry = false;

	/**
	 * Constructs a new success handler with the given JWT payload repository.
	 *
	 * @param payloadRepository the repository for generating JWT payload from authentication
	 */
	public GoogleMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		this.setPayloadRepository(payloadRepository);
	}

	/**
	 * {@inheritDoc}
	 * <p>Supports {@link GoogleAuthenticationToken} instances.</p>
	 */
	@Override
	public boolean supports(Authentication authentication) {
		return SubjectUtils.isAssignableFrom(authentication.getClass(), GoogleAuthenticationToken.class);
	}

	/**
	 * Handles successful authentication by writing the user profile payload as JSON.
	 *
	 * @param request the HTTP servlet request
	 * @param response the HTTP servlet response
	 * @param authentication the authenticated token
	 * @throws IOException if an I/O error occurs
	 * @throws ServletException if a servlet error occurs
	 */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

    	// 设置状态码和响应头
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		// 国际化后的异常信息
		String message = messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey());
		// 用户信息
		SecurityPrincipal principal = (SecurityPrincipal) authentication.getPrincipal();
		UserProfilePayload profilePayload = null;
		if(principal.isBound()){
			profilePayload = getPayloadRepository().getProfilePayload((AbstractAuthenticationToken) authentication, isCheckExpiry());
		} else {
			profilePayload = principal.toPayload();
		}
		JSON.writeTo(response.getOutputStream(), AuthResponse.success(message, profilePayload));
    }

	/**
	 * Returns the JWT payload repository.
	 *
	 * @return the payload repository
	 */
	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	/**
	 * Sets the JWT payload repository.
	 *
	 * @param payloadRepository the payload repository
	 */
	public void setPayloadRepository(JwtPayloadRepository payloadRepository) {
		this.payloadRepository = payloadRepository;
	}

	/**
	 * Returns whether JWT token expiry is checked when building the profile payload.
	 *
	 * @return {@code true} if expiry is checked, {@code false} otherwise
	 */
	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	/**
	 * Sets whether JWT token expiry should be checked when building the profile payload.
	 *
	 * @param checkExpiry {@code true} to check expiry, {@code false} otherwise
	 */
	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}

}
