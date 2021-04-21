package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.google.api.client.googleapis.auth.oauth2.GoogleOAuthConstants;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityGoogleProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityGoogleProperties {

	public static final String PREFIX = "spring.security.google";

	/** Whether Enable Google AccessToken Authentication. */
	private boolean enabled = false;

	/** Public certificates encoded URL. */
	private String publicCertsEncodedUrl = GoogleOAuthConstants.DEFAULT_PUBLIC_CERTS_ENCODED_URL;

	private String proxyHost;

	private int proxyPort;
	
}
