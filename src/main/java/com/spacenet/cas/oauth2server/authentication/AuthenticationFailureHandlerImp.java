package com.spacenet.cas.oauth2server.authentication;

import java.io.IOException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
//ForwardAuthenticationFailureHandler
public class AuthenticationFailureHandlerImp implements AuthenticationFailureHandler {
	
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
			
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		// TODO Auto-generated method stub
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		Map<String, Object> data = new HashMap<>();
		data.put("timestamp", Calendar.getInstance().getTime());
		data.put("exception", exception.getMessage());
		request.setAttribute("authFailureHandler", "Ya valio madres " + exception.getMessage());
		request.getSession().setAttribute("authFailureHandler", "Ya valio madres " + exception.getMessage());

		System.out.println("onAuthenticationFailure AuthenticationException " + exception.getMessage());
		//response.
		
		//RequestDispatcher dispatcher = request.getRequestDispatcher("/user/signin");
		//dispatcher.forward(request, response);
		//HttpServletRequest requestRedirector = request.;
		//request.getRequestDispatcher("/user/signin").forward(request, response);
		this.getRedirectStrategy().sendRedirect(request, response, "/user/signin");

	}

	public RedirectStrategy getRedirectStrategy() {
		return redirectStrategy;
	}

	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

}
