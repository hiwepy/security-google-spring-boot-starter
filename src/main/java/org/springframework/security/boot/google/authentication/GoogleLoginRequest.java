package org.springframework.security.boot.google.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request model binding the Google access token for login authentication.
 * <p>Deserialized from the JSON request body when the client submits a Google
 * access token for authentication.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class GoogleLoginRequest {

	/**
	 * Google access token.
	 */
	private String accessToken;

	/**
	 * Constructs a new login request with the given access token.
	 *
	 * @param accessToken the Google access token
	 */
	@JsonCreator
	public GoogleLoginRequest(@JsonProperty("accessToken") String accessToken) {
		this.accessToken = accessToken;
	}

	/**
	 * Returns the Google access token.
	 *
	 * @return the access token
	 */
	public String getAccessToken() {
		return accessToken;
	}

	/**
	 * Sets the Google access token.
	 *
	 * @param accessToken the access token
	 */
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

}
