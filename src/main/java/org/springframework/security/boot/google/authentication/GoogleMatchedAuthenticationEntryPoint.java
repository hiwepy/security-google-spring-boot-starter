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
package org.springframework.security.boot.google.authentication;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.google.SpringSecurityGoogleMessageSource;
import org.springframework.security.boot.google.exception.GoogleAccessTokenExpiredException;
import org.springframework.security.boot.google.exception.GoogleAccessTokenIncorrectException;
import org.springframework.security.boot.google.exception.GoogleAccessTokenInvalidException;
import org.springframework.security.boot.google.exception.GoogleAccessTokenNotFoundException;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Authentication entry point for Google authentication errors.
 * <p>Handles Google-specific authentication exceptions by writing appropriate
 * JSON error responses with localized messages. Supports expired, incorrect,
 * invalid, and not-found access token exceptions.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class GoogleMatchedAuthenticationEntryPoint implements MatchedAuthenticationEntryPoint {

	protected MessageSourceAccessor messages = SpringSecurityGoogleMessageSource.getAccessor();

	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), GoogleAccessTokenExpiredException.class,
				GoogleAccessTokenIncorrectException.class, GoogleAccessTokenInvalidException.class,
				GoogleAccessTokenNotFoundException.class );
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {

		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());

		if (e instanceof GoogleAccessTokenExpiredException) {
			JSON.writeTo(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED.getMsgKey(), e.getMessage())));
		} else if (e instanceof GoogleAccessTokenIncorrectException) {
			JSON.writeTo(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT.getMsgKey(), e.getMessage())));
		} else if (e instanceof GoogleAccessTokenInvalidException) {
			JSON.writeTo(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_INVALID.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_INVALID.getMsgKey(), e.getMessage())));
		} else if (e instanceof GoogleAccessTokenNotFoundException) {
			JSON.writeTo(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED.getMsgKey(), e.getMessage())));
		}
	}

}
