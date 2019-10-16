package com.ontimize.cloud.security.centralized.feign;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import feign.RequestInterceptor;
import feign.RequestTemplate;

public class FeignSecurityHeaderRequestInterceptor implements RequestInterceptor {
	private static final String AUTHORIZATION_HEADER = "Authorization";

	@Override
	public void apply(RequestTemplate requestTemplate) {
		ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		if (requestAttributes == null) {
			return;
		}
		HttpServletRequest request = requestAttributes.getRequest();
		if (request == null) {
			return;
		}
		String header = request.getHeader(FeignSecurityHeaderRequestInterceptor.AUTHORIZATION_HEADER);
		if (header == null) {
			return;
		}
		requestTemplate.header(FeignSecurityHeaderRequestInterceptor.AUTHORIZATION_HEADER, header);
	}
}