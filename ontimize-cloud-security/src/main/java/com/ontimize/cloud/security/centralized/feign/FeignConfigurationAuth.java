package com.ontimize.cloud.security.centralized.feign;

import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.cloud.netflix.ribbon.SpringClientFactory;
import org.springframework.cloud.openfeign.ribbon.CachingSpringLoadBalancerFactory;
import org.springframework.cloud.openfeign.ribbon.LoadBalancerFeignClient;
import org.springframework.cloud.openfeign.support.ResponseEntityDecoder;
import org.springframework.cloud.openfeign.support.SpringDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;

import com.ontimize.jee.common.jackson.OntimizeMapper;

import feign.Client;
import feign.codec.Decoder;

@Configuration
public class FeignConfigurationAuth {

	@Autowired
	OntimizeMapper ontimizeMapper;

	@Bean
	public Decoder feignDecoder() {
		HttpMessageConverter jacksonConverter = new MappingJackson2HttpMessageConverter(this.ontimizeMapper);
		ObjectFactory<HttpMessageConverters> objectFactory = () -> new HttpMessageConverters(jacksonConverter);
		return new ResponseEntityDecoder(new SpringDecoder(objectFactory));
	}

	@Bean
	public Client feignClient(CachingSpringLoadBalancerFactory cachingFactory, SpringClientFactory clientFactory) {
		return new LoadBalancerFeignClient(new SecurityInterceptorFeignClient(null, null), cachingFactory, clientFactory);
	}

}
