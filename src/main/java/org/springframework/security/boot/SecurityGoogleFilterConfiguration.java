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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.google.authentication.GoogleAuthenticationProcessingFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GooglePublicKeysManager;
import com.google.api.client.util.Clock;
import org.springframework.security.web.savedrequest.RequestCache;

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
	static class GoogleWebSecurityConfigurerAdapter extends SecurityFilterChainConfigurer {

	    private final SecurityGoogleAuthcProperties authcProperties;

	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
		private final LocaleContextFilter localeContextFilter;
		private final LogoutHandler logoutHandler;
		private final LogoutSuccessHandler logoutSuccessHandler;
		private final ObjectMapper objectMapper;
		private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;

		private final GooglePublicKeysManager publicKeysManager;
		private final Clock clock;

		public GoogleWebSecurityConfigurerAdapter(

				SecurityBizProperties bizProperties,
				SecurityGoogleAuthcProperties authcProperties,

				ObjectProvider<GooglePublicKeysManager> publicKeysManagerProvider,
				ObjectProvider<Clock> clockProvider,

				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<LogoutHandler> logoutHandlerProvider,
				ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider

				) {

			super(bizProperties, authcProperties, authenticationProvider.stream().collect(Collectors.toList()));

			this.authcProperties = authcProperties;
			this.publicKeysManager = publicKeysManagerProvider.getIfAvailable();
			this.clock = clockProvider.getIfAvailable(() -> { return Clock.SYSTEM; });

   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
			this.authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
			this.localeContextFilter = localeContextProvider.getIfAvailable();
			this.logoutHandler = super.logoutHandler(logoutHandlerProvider.stream().collect(Collectors.toList()));
			this.logoutSuccessHandler = logoutSuccessHandlerProvider.getIfAvailable();
			this.objectMapper = objectMapperProvider.getIfAvailable();
			this.requestCache = super.requestCache();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
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

		@Bean
		@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 4)
		public SecurityFilterChain googleSecurityFilterChain(HttpSecurity http) throws Exception {
			// new DefaultSecurityFilterChain(new AntPathRequestMatcher(authcProperties.getPathPattern()), localeContextFilter, authenticationProcessingFilter());
			http.antMatcher(authcProperties.getPathPattern())
					// 请求鉴权配置
					.authorizeRequests(this.authorizeRequestsCustomizer())
					// 跨站请求配置
					.csrf(this.csrfCustomizer(authcProperties.getCsrf()))
					// 跨域配置
					.cors(this.corsCustomizer(authcProperties.getCors()))
					// 异常处理
					.exceptionHandling((configurer) -> configurer.authenticationEntryPoint(authenticationEntryPoint))
					// 请求头配置
					.headers(this.headersCustomizer(authcProperties.getHeaders()))
					// Request 缓存配置
					.requestCache((request) -> request.requestCache(requestCache))
					// Session 注销配置
					.logout(this.logoutCustomizer(authcProperties.getLogout(), logoutHandler, logoutSuccessHandler))
					// 禁用 Http Basic
					.httpBasic((basic) -> basic.disable())
					// Filter 配置
					.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
					.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

			return http.build();
		}

	}

}
