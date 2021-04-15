package org.springframework.security.boot.google.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Google AccessToken 登录认证绑定的参数对象Model
 * 
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public class GoogleLoginRequest {

	/**
	 * Google AccessToken
	 */
	private String accessToken;

	@JsonCreator
	public GoogleLoginRequest(@JsonProperty("accessToken") String accessToken) {
		this.accessToken = accessToken;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

}
