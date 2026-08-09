package org.springframework.security.boot;

import com.google.api.client.googleapis.auth.oauth2.GoogleOAuthConstants;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Top-level configuration properties for Google authentication.
 * <p>Binds to the {@code spring.security.google} prefix and controls whether
 * Google ID token authentication is enabled, along with proxy and public certificate settings.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
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

	/** Proxy host for Google API requests. */
	private String proxyHost;

	/** Proxy port for Google API requests. */
	private int proxyPort;

	public boolean isEnabled() { return enabled; }
	public void setEnabled(boolean enabled) { this.enabled = enabled; }
	public String getPublicCertsEncodedUrl() { return publicCertsEncodedUrl; }
	public void setPublicCertsEncodedUrl(String publicCertsEncodedUrl) { this.publicCertsEncodedUrl = publicCertsEncodedUrl; }
	public String getProxyHost() { return proxyHost; }
	public void setProxyHost(String proxyHost) { this.proxyHost = proxyHost; }
	public int getProxyPort() { return proxyPort; }
	public void setProxyPort(int proxyPort) { this.proxyPort = proxyPort; }

}
