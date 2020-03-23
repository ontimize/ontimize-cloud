package com.ontimize.cloud.security.centralized.autoconfigure;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.ontimize.cloud.security.centralized.CentralizedAuthenticationProvider;
import com.ontimize.cloud.security.centralized.CentralizedNodeAuthenticationFilter;
import com.ontimize.cloud.security.centralized.CentralizedSecurityAuthorizator;
import com.ontimize.cloud.security.centralized.ICentralizedAuthProvider;
import com.ontimize.jee.server.security.SecurityConfiguration;
import com.ontimize.jee.server.security.authentication.OntimizeAuthenticationSuccessHandler;
import com.ontimize.jee.server.security.authorization.ISecurityAuthorizator;
import com.ontimize.jee.server.security.authorization.OntimizeAccessDecisionVoter;

@Configuration
@EnableWebSecurity
@ConditionalOnProperty(name = "ontimize.security.mode", havingValue = "centralized", matchIfMissing = false)
public class CentralizedSecurityAutoConfiguration extends WebSecurityConfigurerAdapter {
	@Value("${ontimize.security.servicePath:/**}")
	private String servicePath;

	@Value("${ontimize.security.ignorePaths}")
	private String[] ignorePaths;

	@Autowired
	ICentralizedAuthProvider	remoteAuthInfo;

	/*
	   		.authorizeRequests()
        .antMatchers("/ping**")
        .permitAll()
        .and()
        .authorizeRequests()
        .anyRequest()
        .authenticated()
        .and()
	 */

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.antMatcher(this.servicePath) //
		.exceptionHandling().authenticationEntryPoint(this.authenticationEntryPoint())//
		// private
		.and().csrf().disable().anonymous().disable() // Anonymous disable
		.authorizeRequests().anyRequest().authenticated()
		// no create sessions
		.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
		// ontimize filters
		.and().addFilterBefore(this.preAuthFilterOntimize(), UsernamePasswordAuthenticationFilter.class) //
		.addFilter(this.filterInvocationInterceptor());
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/resources/**");
		if (ignorePaths!=null && ignorePaths.length >0){
			web.ignoring().antMatchers(ignorePaths);
		}
	}

	// @Bean no puede ser un bean porque se configuraria para todos los websecurity de la aplicacion
	public CentralizedNodeAuthenticationFilter preAuthFilterOntimize() throws Exception {
		CentralizedNodeAuthenticationFilter filter = new CentralizedNodeAuthenticationFilter(this.servicePath);
		filter.setAuthenticationManager(this.authenticationManager());
		filter.setAuthenticationEntryPoint(this.authenticationEntryPoint());
		filter.setAuthenticationSuccessHandler(new OntimizeAuthenticationSuccessHandler());
		filter.setAuthInfo(this.remoteAuthInfo);
		filter.afterPropertiesSet();
		return filter;
	}


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(this.authenticationProvider());
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		CentralizedAuthenticationProvider provider = new CentralizedAuthenticationProvider();
		provider.setAuthInfo(this.remoteAuthInfo);
		return provider;
	}

	@Bean
	public AccessDecisionVoter<?> ontimizeAccessDecisionVoter() {
		OntimizeAccessDecisionVoter ontimizeVoter = new OntimizeAccessDecisionVoter();
		ontimizeVoter.setDefaultVoter(this.defaultVoter());
		return ontimizeVoter;
	}

	@Bean
	public RoleVoter defaultVoter() {
		RoleVoter roleVoter = new RoleVoter();
		roleVoter.setRolePrefix("");
		return roleVoter;
	}

	@Bean
	public AccessDecisionManager accessDecisionManager() {
		List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<>();
		decisionVoters.add(this.ontimizeAccessDecisionVoter());
		AffirmativeBased accessDecisionManager = new AffirmativeBased(decisionVoters);
		accessDecisionManager.setAllowIfAllAbstainDecisions(false);
		return accessDecisionManager;
	}

	@Bean
	public ISecurityAuthorizator ontimizeAuthorizator() {
		CentralizedSecurityAuthorizator authorizator = new CentralizedSecurityAuthorizator();
		authorizator.setAuthInfo(this.remoteAuthInfo);
		return authorizator;
	}

	// @Bean no puede ser un bean porque se configuraria para todos los websecurity de la aplicacion
	public FilterSecurityInterceptor filterInvocationInterceptor() throws Exception {
		FilterSecurityInterceptor filterInvocationInterceptor = new FilterSecurityInterceptor();
		filterInvocationInterceptor.setObserveOncePerRequest(true);
		filterInvocationInterceptor.setAuthenticationManager(this.authenticationManager());
		filterInvocationInterceptor.setAccessDecisionManager(this.accessDecisionManager());
		filterInvocationInterceptor.setSecurityMetadataSource(this.filterInvocationSecurityMetadataSource());
		return filterInvocationInterceptor;
	}

	@Bean
	public FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource() {
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
		requestMap.put(new AntPathRequestMatcher("/**/*"), SecurityConfig.createList("NONE_ENTER_WITHOUT_AUTH"));

		ExpressionBasedFilterInvocationSecurityMetadataSource filterSecurityMetadataSource = new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap,
				new DefaultWebSecurityExpressionHandler());
		return filterSecurityMetadataSource;
	}

	@Bean
	public SecurityConfiguration securityConfiguration() {
		SecurityConfiguration securityConfiguration = new SecurityConfiguration();
		securityConfiguration.setAuthorizator(this.ontimizeAuthorizator());
		return securityConfiguration;
	}

	@Bean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		BasicAuthenticationEntryPoint authenticationEntryPoint = new BasicAuthenticationEntryPoint();
		authenticationEntryPoint.setRealmName("ONTIMIZE REALM");
		return authenticationEntryPoint;
	}

}
