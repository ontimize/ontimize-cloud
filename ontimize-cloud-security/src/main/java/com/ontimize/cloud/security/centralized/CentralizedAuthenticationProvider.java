package com.ontimize.cloud.security.centralized;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import com.ontimize.jee.common.exceptions.OntimizeJEEException;

public class CentralizedAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {

	protected final Log					logger						= LogFactory.getLog(this.getClass());

	protected MessageSourceAccessor		messages					= SpringSecurityMessageSource.getAccessor();
	private boolean						forcePrincipalAsString		= false;
	protected boolean					hideUserNotFoundExceptions	= true;
	private UserDetailsChecker			preAuthenticationChecks		= new DefaultPreAuthenticationChecks();
	private UserDetailsChecker			postAuthenticationChecks	= new DefaultPostAuthenticationChecks();
	private GrantedAuthoritiesMapper	authoritiesMapper			= new NullAuthoritiesMapper();
	private ICentralizedAuthProvider			authInfo;

	@Override
	public final void afterPropertiesSet() throws Exception {
		Assert.notNull(this.messages, "A message source must be set");
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		UserDetails user = null;

		try {
			user = this.retrieveUser();
		} catch (Exception notFound) {
			this.logger.debug(null, notFound);
			throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}

		Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");

		this.preAuthenticationChecks.check(user);

		this.postAuthenticationChecks.check(user);

		Object principalToReturn = user;

		if (this.forcePrincipalAsString) {
			principalToReturn = user.getUsername();
		}

		return this.createSuccessAuthentication(principalToReturn, authentication, user);
	}

	private UserDetails retrieveUser() throws OntimizeJEEException {
		return this.authInfo.getUserInformation().toOntimizeUserInformation();
	}

	/**
	 * Creates a successful {@link Authentication} object. <p> Protected so subclasses can override. </p> <p> Subclasses will usually store the original credentials the user
	 * supplied (not salted or encoded passwords) in the returned <code>Authentication</code> object. </p>
	 *
	 * @param principal
	 *            that should be the principal in the returned object (defined by the {@link #isForcePrincipalAsString()} method)
	 * @param authentication
	 *            that was presented to the provider for validation
	 * @param user
	 *            that was loaded by the implementation
	 *
	 * @return the successful authentication token
	 */
	protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
		// Ensure we return the original credentials the user supplied,
		// so subsequent attempts are successful even with encoded passwords.
		// Also ensure we return the original getDetails(), so that future
		// authentication events after cache expiry contain the details
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(principal, authentication.getCredentials(),
				this.authoritiesMapper.mapAuthorities(user.getAuthorities()));
		result.setDetails(authentication.getDetails());

		return result;
	}

	public boolean isForcePrincipalAsString() {
		return this.forcePrincipalAsString;
	}

	public boolean isHideUserNotFoundExceptions() {
		return this.hideUserNotFoundExceptions;
	}

	public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
		this.forcePrincipalAsString = forcePrincipalAsString;
	}

	/**
	 * By default the <code>AbstractUserDetailsAuthenticationProvider</code> throws a <code>BadCredentialsException</code> if a username is not found or the password is incorrect.
	 * Setting this property to <code>false</code> will cause <code>UsernameNotFoundException</code>s to be thrown instead for the former. Note this is considered less secure than
	 * throwing <code>BadCredentialsException</code> for both exceptions.
	 *
	 * @param hideUserNotFoundExceptions
	 *            set to <code>false</code> if you wish <code>UsernameNotFoundException</code>s to be thrown instead of the non-specific <code>BadCredentialsException</code>
	 *            (defaults to <code>true</code>)
	 */
	public void setHideUserNotFoundExceptions(boolean hideUserNotFoundExceptions) {
		this.hideUserNotFoundExceptions = hideUserNotFoundExceptions;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}

	protected UserDetailsChecker getPreAuthenticationChecks() {
		return this.preAuthenticationChecks;
	}

	/**
	 * Sets the policy will be used to verify the status of the loaded <tt>UserDetails</tt> <em>before</em> validation of the credentials takes place.
	 *
	 * @param preAuthenticationChecks
	 *            strategy to be invoked prior to authentication.
	 */
	public void setPreAuthenticationChecks(UserDetailsChecker preAuthenticationChecks) {
		this.preAuthenticationChecks = preAuthenticationChecks;
	}

	protected UserDetailsChecker getPostAuthenticationChecks() {
		return this.postAuthenticationChecks;
	}

	public void setPostAuthenticationChecks(UserDetailsChecker postAuthenticationChecks) {
		this.postAuthenticationChecks = postAuthenticationChecks;
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	public void setAuthInfo(ICentralizedAuthProvider authInfo) {
		this.authInfo = authInfo;
	}

	public ICentralizedAuthProvider getAuthInfo() {
		return this.authInfo;
	}

	private class DefaultPreAuthenticationChecks implements UserDetailsChecker {
		@Override
		public void check(UserDetails user) {
			if (!user.isAccountNonLocked()) {
				CentralizedAuthenticationProvider.this.logger.debug("User account is locked");

				throw new LockedException(CentralizedAuthenticationProvider.this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.locked", "User account is locked"));
			}

			if (!user.isEnabled()) {
				CentralizedAuthenticationProvider.this.logger.debug("User account is disabled");

				throw new DisabledException(CentralizedAuthenticationProvider.this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.disabled", "User is disabled"));
			}

			if (!user.isAccountNonExpired()) {
				CentralizedAuthenticationProvider.this.logger.debug("User account is expired");

				throw new AccountExpiredException(
						CentralizedAuthenticationProvider.this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.expired", "User account has expired"));
			}
		}
	}

	private class DefaultPostAuthenticationChecks implements UserDetailsChecker {
		@Override
		public void check(UserDetails user) {
			if (!user.isCredentialsNonExpired()) {
				CentralizedAuthenticationProvider.this.logger.debug("User account credentials have expired");

				throw new CredentialsExpiredException(
						CentralizedAuthenticationProvider.this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.credentialsExpired", "User credentials have expired"));
			}
		}
	}
}
