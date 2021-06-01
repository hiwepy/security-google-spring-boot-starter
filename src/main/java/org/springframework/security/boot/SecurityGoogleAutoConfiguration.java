package org.springframework.security.boot;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.google.authentication.GoogleAuthenticationProcessingFilter;
import org.springframework.security.boot.google.authentication.GoogleAuthenticationProvider;
import org.springframework.security.boot.google.authentication.GoogleMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.google.authentication.GoogleMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.google.authentication.GoogleMatchedAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
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
	
	@Bean
	public GoogleAuthenticationProcessingFilter authenticationProcessingFilter(
			
			SecurityGoogleAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			
			ObjectProvider<GooglePublicKeysManager> publicKeysManagerProvider,
			ObjectProvider<Clock> clockProvider,
			ObjectProvider<AuthenticationProvider> authenticationProvider,
			ObjectProvider<AuthenticationManager> authenticationManagerProvider,
			ObjectProvider<AuthenticationListener> authenticationListenerProvider,
			ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
			ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
			ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
			ObjectProvider<ObjectMapper> objectMapperProvider,
			ObjectProvider<RememberMeServices> rememberMeServicesProvider) throws Exception {
    	
		GooglePublicKeysManager publicKeysManager = publicKeysManagerProvider.getIfAvailable();
		Clock clock = clockProvider.getIfAvailable(() -> { return Clock.SYSTEM; });
		List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
		MatchedAuthenticationEntryPoint authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
			this.objectMapper = objectMapperProvider.getIfAvailable();
			this.requestCache = super.requestCache();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			this.sessionAuthenticationStrategy = super.sessionAuthenticationStrategy();
			
		GoogleAuthenticationProcessingFilter authenticationFilter = new GoogleAuthenticationProcessingFilter(objectMapper);
		
		/**
		 * 批量设置参数
		 */
		PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
		
		map.from(sessionMgtProperties.isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
		
		map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
		map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
		map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
		
		map.from(authcProperties.getClientIds()).to(authenticationFilter::setClientIds);
		map.from(this.publicKeysManager).to(authenticationFilter::setPublicKeysManager);
		map.from(this.clock).to(authenticationFilter::setClock);
		map.from(authcProperties.getAcceptableTimeSkewSeconds()).to(authenticationFilter::setAcceptableTimeSkewSeconds);
		
		map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
		map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
		map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
		map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
		
        return authenticationFilter;
    }

}
