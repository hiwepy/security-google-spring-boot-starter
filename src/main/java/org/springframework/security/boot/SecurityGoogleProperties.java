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
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = SecurityGoogleProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityGoogleProperties {

	/**
	 * Returns the enabled.
	 *
	 * @return the enabled
	 */
	public static final String PREFIX = "spring.security.google";

	/** Whether Enable Google AccessToken Authentication. */
	private boolean enabled = false;

	/** Public certificates encoded URL. */
	private String publicCertsEncodedUrl = GoogleOAuthConstants.DEFAULT_PUBLIC_CERTS_ENCODED_URL;

	/** Proxy host for Google API requests. */
	private String proxyHost;

	/** Proxy port for Google API requests. */
	private int proxyPort;

	/**
	 * Returns the enabled.
	 *
	 * @return the enabled
	 */
	public boolean isEnabled() { return enabled; }
	/**
	 * Sets the enabled.
	 *
	 * @param enabled the enabled
	 */
	public void setEnabled(boolean enabled) { this.enabled = enabled; }
	/**
	 * Returns the public certs encoded url.
	 *
	 * @return the public certs encoded url
	 */
	public String getPublicCertsEncodedUrl() { return publicCertsEncodedUrl; }
	/**
	 * Sets the public certs encoded url.
	 *
	 * @param publicCertsEncodedUrl the public certs encoded url
	 */
	public void setPublicCertsEncodedUrl(String publicCertsEncodedUrl) { this.publicCertsEncodedUrl = publicCertsEncodedUrl; }
	/**
	 * Returns the proxy host.
	 *
	 * @return the proxy host
	 */
	public String getProxyHost() { return proxyHost; }
	/**
	 * Sets the proxy host.
	 *
	 * @param proxyHost the proxy host
	 */
	public void setProxyHost(String proxyHost) { this.proxyHost = proxyHost; }
	/**
	 * Returns the proxy port.
	 *
	 * @return the proxy port
	 */
	public int getProxyPort() { return proxyPort; }
	/**
	 * Sets the proxy port.
	 *
	 * @param proxyPort the proxy port
	 */
	public void setProxyPort(int proxyPort) { this.proxyPort = proxyPort; }

}
