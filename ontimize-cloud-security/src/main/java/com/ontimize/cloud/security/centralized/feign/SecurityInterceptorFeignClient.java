package com.ontimize.cloud.security.centralized.feign;

import java.io.IOException;
import java.util.Collection;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.ontimize.jee.server.security.authentication.OntimizeAuthenticationFilter;

import feign.Client.Default;
import feign.Request;
import feign.Request.Options;
import feign.Response;

/**
 * The Class SecurityInterceptorFeignClient. Establish X-Auth-Token header from security response to main request.
 */
public class SecurityInterceptorFeignClient extends Default {

	/**
	 * Instantiates a new security interceptor feign client.
	 *
	 * @param sslContextFactory
	 *            the ssl context factory
	 * @param hostnameVerifier
	 *            the hostname verifier
	 */
	public SecurityInterceptorFeignClient(SSLSocketFactory sslContextFactory, HostnameVerifier hostnameVerifier) {
		super(sslContextFactory, hostnameVerifier);
	}

	/*
	 * (non-Javadoc)
	 * @see feign.Client.Default#execute(feign.Request, feign.Request.Options)
	 */
	@Override
	public Response execute(Request request, Options options) throws IOException {
		Response response = super.execute(request, options);
		this.updateSecurityHeader(response);
		return response;
	}

	private void updateSecurityHeader(Response response) {
		ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		if (requestAttributes != null) {
			HttpServletResponse mainResponse = requestAttributes.getResponse();
			if (mainResponse != null) {
				String header = mainResponse.getHeader(OntimizeAuthenticationFilter.DEFAULT_TOKEN_HEADER);
				Collection<String> responseHeaders = response.headers().get(OntimizeAuthenticationFilter.DEFAULT_TOKEN_HEADER);
				if ((header == null) && (responseHeaders != null) && (!responseHeaders.isEmpty())) {
					mainResponse.setHeader(OntimizeAuthenticationFilter.DEFAULT_TOKEN_HEADER, responseHeaders.iterator().next());
				}
			}
		}
	}

}