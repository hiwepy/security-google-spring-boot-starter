package org.springframework.security.boot.google.authentication;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.google.SpringSecurityGoogleMessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;

/**
 * Google 认证 (authentication) 处理器
 */
@Slf4j
public class GoogleAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityGoogleMessageSource.getAccessor();
    private final UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    public GoogleAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (GoogleAuthenticationToken.class.isAssignableFrom(authentication));
    }
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (log.isDebugEnabled()) {
    		log.debug("Processing authentication request : " + authentication);
		}
    	
    	GoogleAuthenticationToken token = (GoogleAuthenticationToken) authentication;
        
        UserDetails ud = getUserDetailsService().loadUserDetails(authentication);
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        GoogleAuthenticationToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	SecurityPrincipal principal = (SecurityPrincipal) ud;
        	principal.setSign(token.getSign());
    		principal.setLongitude(token.getLongitude());
    		principal.setLatitude(token.getLatitude());
        	authenticationToken = new GoogleAuthenticationToken(ud, token.getAccessToken(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new GoogleAuthenticationToken(token.getPrincipal(), token.getAccessToken(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
}
