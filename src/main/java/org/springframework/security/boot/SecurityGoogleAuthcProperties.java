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
package org.springframework.security.boot;

import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.google.authentication.GoogleAuthenticationProcessingFilter;

import java.util.List;

/**
 * Configuration properties for Google ID token authentication.
 * <p>Binds to the {@code spring.security.google.authc} prefix and extends
 * the common authentication properties with Google-specific settings such as
 * acceptable time skew and allowed client IDs.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConfigurationProperties(SecurityGoogleAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityGoogleAuthcProperties extends SecurityAuthcProperties {

	/**
	 * Returns the authorization param name.
	 *
	 * @return the authorization param name
	 */
	public static final String PREFIX = "spring.security.google.authc";

	/** Authorization Path Pattern */
	private String pathPattern = "/**";
	
	/** the token parameter name. Defaults to "token". */
	private String authorizationParamName = GoogleAuthenticationProcessingFilter.AUTHORIZATION_PARAM;

    /** Seconds of time skew to accept when verifying time. */
	private long acceptableTimeSkewSeconds = IdTokenVerifier.DEFAULT_TIME_SKEW_SECONDS;
	
	/** List of allowed Google OAuth client IDs for ID token audience verification. */
	private List<String> clientIds;

	/**
	 * Returns the authorization param name.
	 *
	 * @return the authorization param name
	 */
	public String getAuthorizationParamName() { return authorizationParamName; }
	/**
	 * Sets the authorization param name.
	 *
	 * @param authorizationParamName the authorization param name
	 */
	public void setAuthorizationParamName(String authorizationParamName) { this.authorizationParamName = authorizationParamName; }
	/**
	 * Returns the acceptable time skew seconds.
	 *
	 * @return the acceptable time skew seconds
	 */
	public long getAcceptableTimeSkewSeconds() { return acceptableTimeSkewSeconds; }
	/**
	 * Sets the acceptable time skew seconds.
	 *
	 * @param acceptableTimeSkewSeconds the acceptable time skew seconds
	 */
	public void setAcceptableTimeSkewSeconds(long acceptableTimeSkewSeconds) { this.acceptableTimeSkewSeconds = acceptableTimeSkewSeconds; }
	/**
	 * Returns the client ids.
	 *
	 * @return the client ids
	 */
	public List<String> getClientIds() { return clientIds; }
	/**
	 * Sets the client ids.
	 *
	 * @param clientIds the client ids
	 */
	public void setClientIds(List<String> clientIds) { this.clientIds = clientIds; }

}
