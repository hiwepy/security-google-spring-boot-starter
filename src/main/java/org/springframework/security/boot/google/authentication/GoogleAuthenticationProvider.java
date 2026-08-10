package org.springframework.security.boot.google.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

/**
 * Authentication provider for Google ID token authentication.
 * <p>Validates {@link GoogleAuthenticationToken} instances by loading
 * user details via the configured {@link UserDetailsServiceAdapter}, performing
 * user status checks, and returning an authenticated token with granted authorities.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class GoogleAuthenticationProvider implements AuthenticationProvider {

	private static final Logger log = LoggerFactory.getLogger(GoogleAuthenticationProvider.class);
	protected MessageSourceAccessor messages = SpringSecurityGoogleMessageSource.getAccessor();
    private final UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    /**
     * Constructs a new provider with the given user details service.
     *
     * @param userDetailsService the user details service adapter for loading user details
     */
    public GoogleAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * {@inheritDoc}
     * <p>Supports {@link GoogleAuthenticationToken} instances.</p>
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (GoogleAuthenticationToken.class.isAssignableFrom(authentication));
    }

    /**
     * Authenticates the given {@link GoogleAuthenticationToken} by loading user details
     * and performing user status checks.
     *
     * @param authentication the authentication token to authenticate
     * @return the authenticated token with granted authorities
     * @throws AuthenticationException if authentication fails
     */
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

    /**
     * Sets the user details checker used to verify user account status.
     *
     * @param userDetailsChecker the user details checker
     */
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	/**
	 * Returns the user details checker used to verify user account status.
	 *
	 * @return the user details checker
	 */
	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	/**
	 * Returns the user details service adapter.
	 *
	 * @return the user details service adapter
	 */
	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
}
