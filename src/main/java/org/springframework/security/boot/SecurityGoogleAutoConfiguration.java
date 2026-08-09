package org.springframework.security.boot;

import com.google.api.client.googleapis.auth.oauth2.GooglePublicKeysManager;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.Clock;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.google.authentication.GoogleAuthenticationProvider;
import org.springframework.security.boot.google.authentication.GoogleMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.google.authentication.GoogleMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.google.authentication.GoogleMatchedAuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import java.security.GeneralSecurityException;

/**
 * Auto-configuration for Google authentication beans.
 * <p>Registers the HTTP transport, JSON factory, public keys manager, entry point,
 * failure handler, success handler, and authentication provider required for Google
 * ID token authentication. Activated only when {@code spring.security.google.enabled=true}.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityGoogleProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityGoogleProperties.class })
public class SecurityGoogleAutoConfiguration {

	private static final String SHOULD_USE_PROXY_FLAG = "com.google.api.client.should_use_proxy";

	/**
	 * Creates an {@link HttpTransport} for Google API communication.
	 * <p>If a proxy host is configured, the transport is built with proxy settings
	 * and certificate validation disabled.</p>
	 *
	 * @param googleProperties the Google configuration properties
	 * @return the HTTP transport
	 * @throws GeneralSecurityException if transport creation fails
	 */
	@Bean
	@ConditionalOnMissingBean
	public HttpTransport transport(SecurityGoogleProperties googleProperties) throws GeneralSecurityException {
		if(StringUtils.hasText(googleProperties.getProxyHost())) {
			System.setProperty(SHOULD_USE_PROXY_FLAG, googleProperties.getProxyHost());
			System.setProperty("https.proxyHost", googleProperties.getProxyHost());
			System.setProperty("https.proxyPort", String.valueOf(googleProperties.getProxyPort()));
			return new NetHttpTransport.Builder().doNotValidateCertificate().build();
		}
		return new NetHttpTransport();
	}
	
	/**
	 * Creates a {@link JsonFactory} for JSON serialization/deserialization.
	 *
	 * @return a Gson-based JSON factory
	 */
	@Bean
	@ConditionalOnMissingBean
	public JsonFactory jsonFactory() {
		return new GsonFactory();
	}

	/**
	 * Creates a {@link GooglePublicKeysManager} for fetching Google's public certificates.
	 *
	 * @param transport the HTTP transport
	 * @param jsonFactory the JSON factory
	 * @param clockProvider provider for the clock (defaults to system clock)
	 * @param googleProperties the Google configuration properties
	 * @return the public keys manager
	 * @throws GeneralSecurityException if manager creation fails
	 */
	@Bean
	@ConditionalOnMissingBean
	public GooglePublicKeysManager googlePublicKeysManager(HttpTransport transport,
			JsonFactory jsonFactory,
			ObjectProvider<Clock> clockProvider,
			SecurityGoogleProperties googleProperties) throws GeneralSecurityException {
		return new GooglePublicKeysManager.Builder(transport, jsonFactory)
					.setPublicCertsEncodedUrl(googleProperties.getPublicCertsEncodedUrl())
					.setClock(clockProvider.getIfAvailable(() -> { return Clock.SYSTEM; }))
					.build();
	}
	
	/**
	 * Creates a {@link GoogleMatchedAuthenticationEntryPoint} if no existing bean is present.
	 *
	 * @return the authentication entry point for Google authentication errors
	 */
	@Bean
	@ConditionalOnMissingBean
	public GoogleMatchedAuthenticationEntryPoint googleMatchedAuthenticationEntryPoint() {
		return new GoogleMatchedAuthenticationEntryPoint();
	}

	/**
	 * Creates a {@link GoogleMatchedAuthenticationFailureHandler} if no existing bean is present.
	 *
	 * @return the authentication failure handler for Google authentication
	 */
	@Bean
	@ConditionalOnMissingBean
	public GoogleMatchedAuthenticationFailureHandler googleMatchedAuthenticationFailureHandler() {
		return new GoogleMatchedAuthenticationFailureHandler();
	}

	/**
	 * Creates a {@link GoogleMatchedAuthenticationSuccessHandler} if no existing bean is present.
	 *
	 * @param payloadRepository the JWT payload repository for generating user profile payloads
	 * @return the authentication success handler for Google authentication
	 */
	@Bean
	@ConditionalOnMissingBean
	public GoogleMatchedAuthenticationSuccessHandler googleMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new GoogleMatchedAuthenticationSuccessHandler(payloadRepository);
	}

	/**
	 * Creates a {@link GoogleAuthenticationProvider} if no existing bean is present.
	 *
	 * @param userDetailsService the user details service adapter for loading user details
	 * @return the authentication provider for Google ID token authentication
	 */
	@Bean
	@ConditionalOnMissingBean
	public GoogleAuthenticationProvider googleAuthenticationProvider(UserDetailsServiceAdapter userDetailsService) {
		return new GoogleAuthenticationProvider(userDetailsService);
	}

}
