package org.springframework.security.boot;

import java.security.GeneralSecurityException;

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

import com.google.api.client.googleapis.auth.oauth2.GooglePublicKeysManager;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.Clock;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityGoogleProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityGoogleProperties.class })
public class SecurityGoogleAutoConfiguration {

	private static final String SHOULD_USE_PROXY_FLAG = "com.google.api.client.should_use_proxy";

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
	
	@Bean
	@ConditionalOnMissingBean
	public JsonFactory jsonFactory() {
		return new GsonFactory();
	}

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
	
	@Bean
	@ConditionalOnMissingBean
	public GoogleMatchedAuthenticationEntryPoint googleMatchedAuthenticationEntryPoint() {
		return new GoogleMatchedAuthenticationEntryPoint();
	}

	@Bean
	@ConditionalOnMissingBean
	public GoogleMatchedAuthenticationFailureHandler googleMatchedAuthenticationFailureHandler() {
		return new GoogleMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public GoogleMatchedAuthenticationSuccessHandler googleMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new GoogleMatchedAuthenticationSuccessHandler(payloadRepository);
	}

	@Bean
	@ConditionalOnMissingBean
	public GoogleAuthenticationProvider googleAuthenticationProvider(UserDetailsServiceAdapter userDetailsService) {
		return new GoogleAuthenticationProvider(userDetailsService);
	}

}
