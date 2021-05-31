package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.google.authentication.GoogleAuthenticationProcessingFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GooglePublicKeysManager;
import com.google.api.client.util.Clock;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration"
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityGoogleProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityGoogleProperties.class, SecurityGoogleAuthcProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityGoogleFilterConfiguration {
	
	@Configuration
	@EnableConfigurationProperties({ SecurityGoogleProperties.class, SecurityGoogleAuthcProperties.class, SecurityBizProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 4)
	static class GoogleWebSecurityConfigurerAdapter extends WebSecurityBizConfigurerAdapter {

	    private final SecurityGoogleAuthcProperties authcProperties;

	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final ObjectMapper objectMapper;
    	private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final LocaleContextFilter localeContextFilter;
		private final GooglePublicKeysManager publicKeysManager;
		private final Clock clock;
		
		public GoogleWebSecurityConfigurerAdapter(
   				
				SecurityBizProperties bizProperties,
				SecurityGoogleAuthcProperties authcProperties,
				SecuritySessionMgtProperties sessionMgtProperties,
				
				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<GooglePublicKeysManager> publicKeysManagerProvider,
				ObjectProvider<Clock> clockProvider,
				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider
   				
				) {
			
			super(bizProperties, authcProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()),
					authenticationManagerProvider.getIfAvailable());
   			
			this.authcProperties = authcProperties;
			this.localeContextFilter = localeContextProvider.getIfAvailable();
			this.publicKeysManager = publicKeysManagerProvider.getIfAvailable();
			this.clock = clockProvider.getIfAvailable(() -> { return Clock.SYSTEM; });
   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.requestCache = super.requestCache();
   			this.rememberMeServices = super.rememberMeServices();
   			this.sessionAuthenticationStrategy = super.sessionAuthenticationStrategy();
		}

		
		public GoogleAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
			GoogleAuthenticationProcessingFilter authenticationFilter = new GoogleAuthenticationProcessingFilter(this.objectMapper);
			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(authcProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
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
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			
			http.requestCache()
	        	.requestCache(requestCache)
	        	.and()
	        	.exceptionHandling()
	        	.authenticationEntryPoint(authenticationEntryPoint)
	        	.and()
	        	.httpBasic()
	        	.disable()
   	        	.antMatcher(authcProperties.getPathPattern())
   	        	.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
   	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 
   	    	
   	    	super.configure(http, authcProperties.getCors());
   	    	super.configure(http, authcProperties.getCsrf());
   	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
		}
		
		@Override
	    public void configure(WebSecurity web) throws Exception {
	    	super.configure(web);
	    }
		
	}
	
}
