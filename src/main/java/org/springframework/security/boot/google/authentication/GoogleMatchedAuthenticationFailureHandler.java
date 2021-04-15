package org.springframework.security.boot.google.authentication;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.google.exception.GoogleAcceccTokenNotFoundException;
import org.springframework.security.boot.google.exception.GoogleIdTokenVerifierException;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

/**
 * Google认证请求失败后的处理实现
 */
public class GoogleMatchedAuthenticationFailureHandler implements MatchedAuthenticationFailureHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), GoogleAcceccTokenNotFoundException.class, 
				GoogleIdTokenVerifierException.class);
	}
	
}
