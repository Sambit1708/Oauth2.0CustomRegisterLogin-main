package com.oauth.implementation.config;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import com.oauth.implementation.dao.UserRepository;
import com.oauth.implementation.model.User;


@Component
public class AuthFilter implements Filter{
	
	private static final List<String> EXCLUDED_ENDPOINTS = Arrays.asList("/registration/**", "/login/**");
	
	private final AntPathMatcher pathMatcher = new AntPathMatcher();
	
	@Autowired
	UserRepository userRepo;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		String requestURI = httpRequest.getRequestURI();
		boolean isExcludedEndpoint = EXCLUDED_ENDPOINTS.stream()
				.anyMatch(pattern -> pathMatcher.match(pattern, requestURI));
		if (isExcludedEndpoint) {
			chain.doFilter(request, response);
			return;
		} else {
			SecurityContext securityContext = SecurityContextHolder.getContext();
			if(securityContext.getAuthentication().getPrincipal() instanceof DefaultOAuth2User) {
				DefaultOAuth2User userDetails = (DefaultOAuth2User) securityContext.getAuthentication().getPrincipal();
				String username = userDetails.getAttribute("email") != null ? userDetails.getAttribute("email")
						: userDetails.getAttribute("login") + "@gmail.com";
				User user = this.userRepo.findByEmail(username);
				if (user != null) {
					if (user.isActive()) {
						chain.doFilter(request, response);
					} else {
						HttpServletResponse httpResponse = (HttpServletResponse) response;
		                httpResponse.sendRedirect("/login");
					}
				} else {
					HttpServletResponse httpResponse = (HttpServletResponse) response;
	                httpResponse.sendRedirect("/login");
				}
			}
			else if (securityContext.getAuthentication() != null) {
				UserDetails user = (UserDetails) securityContext.getAuthentication().getPrincipal();
				User users = userRepo.findByEmail(user.getUsername());
				if (users.isActive()) {
					chain.doFilter(request, response);
				} else {
					HttpServletResponse httpResponse = (HttpServletResponse) response;
	                httpResponse.sendRedirect("/login");
				}
			}else {
				HttpServletResponse httpResponse = (HttpServletResponse) response;
                httpResponse.sendRedirect("/login");
			}
		}
	}

}
