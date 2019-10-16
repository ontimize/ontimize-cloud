package com.ontimize.cloud.security.centralized;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

import com.ontimize.jee.server.security.authentication.OntimizeAuthenticationFilter;
import com.ontimize.jee.server.security.authentication.OntimizeAuthenticationSuccessHandler;
import com.ontimize.jee.server.security.authentication.OntimizeWebAuthenticationDetailsSource;

public class CentralizedNodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static final Logger										logger						= LoggerFactory.getLogger(OntimizeAuthenticationFilter.class);

	protected AuthenticationDetailsSource<HttpServletRequest, ?>	authenticationDetailsSource	= new OntimizeWebAuthenticationDetailsSource();

	private AuthenticationEntryPoint								authenticationEntryPoint;
	private ICentralizedAuthProvider										authInfo;

	public CentralizedNodeAuthenticationFilter() {
		this("/**");
	}

	public CentralizedNodeAuthenticationFilter(String path) {
		super(path);
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(this.authenticationEntryPoint, "authenticationEntryPoint property is mandatory");
		this.setAuthenticationSuccessHandler(new OntimizeAuthenticationSuccessHandler());
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return true;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (!this.requiresAuthentication(request, response)) {
			chain.doFilter(request, response);

			return;
		}

		if (CentralizedNodeAuthenticationFilter.logger.isDebugEnabled()) {
			CentralizedNodeAuthenticationFilter.logger.debug("Request is to process authentication");
		}

		Authentication authResult;

		try {
			authResult = this.attemptAuthentication(request, response);
			if (authResult != null) {
				this.successfulAuthentication(request, response, chain, authResult);
			}
			chain.doFilter(request, response);
		} catch (InternalAuthenticationServiceException failed) {
			CentralizedNodeAuthenticationFilter.logger.error("An internal error occurred while trying to authenticate the user.", failed);
			this.unsuccessfulAuthentication(request, response, failed);
		} catch (AuthenticationException failed) {
			// Authentication failed
			this.unsuccessfulAuthentication(request, response, failed);
		}
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
		try {
			Authentication authentication = this.getAuthenticationManager().authenticate(new TestingAuthenticationToken(null, null));

			if (authentication instanceof AbstractAuthenticationToken) {
				((AbstractAuthenticationToken) authentication).setDetails(this.authenticationDetailsSource.buildDetails(request));
			}
			// this.successfulLogin(request, response, authentication);
			return authentication;
		} catch (AuthenticationException authEx) {
			this.authenticationEntryPoint.commence(request, response, authEx);
			throw authEx;
		}
	}

	// protected void successfulLogin(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {
	// ProxyNodeAuthenticationFilter.logger.debug("Authentication request success: {}", authResult);
	// String token = this.generateToken(request, authResult);
	// response.setHeader(OntimizeAuthenticationFilter.DEFAULT_TOKEN_HEADER, token);
	// }

	// public String generateToken(HttpServletRequest request, Authentication authResult) {
	// return this.authInfo.requestToken();
	// }



	public AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.authenticationEntryPoint;
	}

	public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	public void setAuthInfo(ICentralizedAuthProvider authInfo) {
		this.authInfo = authInfo;
	}

	public ICentralizedAuthProvider getAuthInfo() {
		return this.authInfo;
	}
}
