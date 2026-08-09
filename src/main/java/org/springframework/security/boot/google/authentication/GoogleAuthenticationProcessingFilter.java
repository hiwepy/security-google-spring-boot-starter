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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GooglePublicKeysManager;
import com.google.api.client.util.Clock;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.AuthenticationProcessingFilter;
import org.springframework.security.boot.google.exception.GoogleAccessTokenIncorrectException;
import org.springframework.security.boot.google.exception.GoogleAccessTokenInvalidException;
import org.springframework.security.boot.google.exception.GoogleAccessTokenNotFoundException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Objects;

/**
 * Authentication processing filter for Google ID token login.
 * <p>Intercepts requests to the Google login endpoint, extracts the ID token
 * from the request body or query parameters, verifies it using the
 * {@link GoogleIdTokenVerifier}, and creates a {@link GoogleAuthenticationToken}
 * for authentication.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 * @see <a href="https://developers.google.com/identity/sign-in/android/backend-auth">Google Backend Auth</a>
 */
public class GoogleAuthenticationProcessingFilter extends AuthenticationProcessingFilter {

	/**
	 * HTTP Authorization Param, equal to <code>accessToken</code>
	 */
	public static final String AUTHORIZATION_PARAM = "accessToken";
	private ObjectMapper objectMapper = new ObjectMapper();
	private GooglePublicKeysManager publicKeysManager;
	private String authorizationParamName = AUTHORIZATION_PARAM;
	private List<String> clientIds;
    /** Clock. */
	private Clock clock = Clock.SYSTEM;
    /** Seconds of time skew to accept when verifying time. */
	private long acceptableTimeSkewSeconds = IdTokenVerifier.DEFAULT_TIME_SKEW_SECONDS;
    
    /**
     * Constructs a new filter with the given object mapper.
     *
     * @param objectMapper the Jackson object mapper for JSON deserialization
     */
    public GoogleAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(PathPatternRequestMatcher.pathPattern("/login/google"));
    	this.objectMapper = objectMapper;
    }

    /**
     * Attempts to authenticate the request by extracting the Google ID token,
     * verifying it against Google's public keys, and returning an authenticated token.
     *
     * @param request the HTTP servlet request
     * @param response the HTTP servlet response
     * @return the authenticated {@link Authentication} object
     * @throws AuthenticationException if authentication fails
     * @throws IOException if an I/O error occurs
     * @throws ServletException if a servlet error occurs
     */
    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
 
    	String idTokenString = "";
    	
		// Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			
			GoogleLoginRequest loginRequest = objectMapper.readValue(request.getReader(), GoogleLoginRequest.class);
			idTokenString = loginRequest.getAccessToken();

		} else {
			
			idTokenString = this.obtainAccessToken(request);
	 		
		}

		if (idTokenString == null) {
			idTokenString = "";
		}
		
		idTokenString = idTokenString.trim();
		
		if(StringUtils.isBlank(idTokenString)) {
			throw new GoogleAccessTokenNotFoundException("accessToken not provided");
		}
		
		try {
			
			GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(publicKeysManager)
			    .setAcceptableTimeSkewSeconds(acceptableTimeSkewSeconds)
				.setClock(clock)
			    // Specify the CLIENT_ID of the app that accesses the backend:
			    //.setAudience(Collections.singletonList(clientId))
			    // Or, if multiple clients access the backend:
			    .setAudience(clientIds)
			    .build();

			GoogleIdToken idToken = verifier.verify(idTokenString);
			if (Objects.isNull(idToken)) {
				throw new GoogleAccessTokenInvalidException(" Google Id Token Invalid ");
			}
			
			GoogleAuthenticationToken authRequest = new GoogleAuthenticationToken(idToken, idTokenString);
			authRequest.setAppId(this.obtainAppId(request));
			authRequest.setAppChannel(this.obtainAppChannel(request));
			authRequest.setAppVersion(this.obtainAppVersion(request));
			authRequest.setUid(this.obtainUid(request));
			authRequest.setLongitude(this.obtainLongitude(request));
			authRequest.setLatitude(this.obtainLatitude(request));
			authRequest.setSign(this.obtainSign(request));
			
			// Allow subclasses to set the "details" property
			setDetails(request, authRequest);

			return this.getAuthenticationManager().authenticate(authRequest);
			
		} catch (GeneralSecurityException e) {
			throw new GoogleAccessTokenIncorrectException(" Google Id Token Verifier Exception : ", e);
		}

    }
    
	/**
	 * Extracts the access token from the HTTP request parameters.
	 *
	 * @param request the HTTP servlet request
	 * @return the access token, or {@code null} if not present
	 */
	protected String obtainAccessToken(HttpServletRequest request) {
		String token = request.getParameter(getAuthorizationParamName());
		return token;
	}

	/**
	 * Sets the details on the authentication token using the authentication details source.
	 *
	 * @param request the HTTP servlet request
	 * @param authRequest the authentication token to populate
	 */
	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}

	/**
	 * Returns the name of the request parameter that carries the access token.
	 *
	 * @return the authorization parameter name
	 */
	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	/**
	 * Sets the name of the request parameter that carries the access token.
	 *
	 * @param authorizationParamName the authorization parameter name
	 */
	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}

	/**
	 * Returns the Google public keys manager used for ID token verification.
	 *
	 * @return the public keys manager
	 */
	public GooglePublicKeysManager getPublicKeysManager() {
		return publicKeysManager;
	}

	/**
	 * Sets the Google public keys manager used for ID token verification.
	 *
	 * @param publicKeysManager the public keys manager
	 */
	public void setPublicKeysManager(GooglePublicKeysManager publicKeysManager) {
		this.publicKeysManager = publicKeysManager;
	}

	/**
	 * Returns the list of allowed Google OAuth client IDs.
	 *
	 * @return the list of client IDs
	 */
	public List<String> getClientIds() {
		return clientIds;
	}

	/**
	 * Sets the list of allowed Google OAuth client IDs.
	 *
	 * @param clientIds the list of client IDs
	 */
	public void setClientIds(List<String> clientIds) {
		this.clientIds = clientIds;
	}

	/**
	 * Returns the clock used for ID token time verification.
	 *
	 * @return the clock
	 */
	public Clock getClock() {
		return clock;
	}

	/**
	 * Sets the clock used for ID token time verification.
	 *
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		this.clock = clock;
	}

	/**
	 * Returns the acceptable time skew in seconds for ID token verification.
	 *
	 * @return the acceptable time skew in seconds
	 */
	public long getAcceptableTimeSkewSeconds() {
		return acceptableTimeSkewSeconds;
	}

	/**
	 * Sets the acceptable time skew in seconds for ID token verification.
	 *
	 * @param acceptableTimeSkewSeconds the acceptable time skew in seconds
	 */
	public void setAcceptableTimeSkewSeconds(long acceptableTimeSkewSeconds) {
		this.acceptableTimeSkewSeconds = acceptableTimeSkewSeconds;
	}

}
