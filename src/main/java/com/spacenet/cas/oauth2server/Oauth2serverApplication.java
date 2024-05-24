package com.spacenet.cas.oauth2server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.jackson2.CoreJackson2Module;

import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootApplication
public class Oauth2serverApplication {

	public static void main(String[] args) {
		SpringApplication.run(Oauth2serverApplication.class, args);
	}
	
	@Bean(name="bCrypt")
	public BCryptPasswordEncoder passwordEncoderBCriypt() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web)-> web.ignoring().requestMatchers("/webjars/**");
	}
	
	/*@Bean
	public ObjectMapper objectMapper() {
	    ObjectMapper mapper = new ObjectMapper();
	    mapper.registerModule(new CoreJackson2Module());
	    // ... your other configuration
	    return mapper;
	}*/
}
