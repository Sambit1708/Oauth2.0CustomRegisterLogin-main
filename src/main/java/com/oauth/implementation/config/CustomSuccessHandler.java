package com.oauth.implementation.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.oauth.implementation.dao.UserRepository;
import com.oauth.implementation.dto.UserRegisteredDTO;
import com.oauth.implementation.model.User;
import com.oauth.implementation.service.DefaultUserService;

@Component
public class CustomSuccessHandler implements AuthenticationSuccessHandler {

	@Autowired
	UserRepository userRepo;

	@Autowired
	DefaultUserService userService;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		String redirectUrl = "/login";
		if (authentication.getPrincipal() instanceof DefaultOAuth2User) {
			DefaultOAuth2User userDetails = (DefaultOAuth2User) authentication.getPrincipal();
			String username = userDetails.getAttribute("email") != null ? userDetails.getAttribute("email")
					: userDetails.getAttribute("login") + "@gmail.com";
			if (userRepo.findByEmail(username) == null) {
				UserRegisteredDTO user = new UserRegisteredDTO();
				user.setEmail_id(username);
				user.setName(userDetails.getAttribute("email") != null ? userDetails.getAttribute("email")
						: userDetails.getAttribute("login"));
				user.setPassword(("Dummy"));
				user.setRole("USER");
				user.setPhoneNumber("+9163702255180");
				userService.save(user);
			}
			else {
				User userOtp = this.userRepo.findByEmail(username);
				String output = userService.generateOtp(userOtp);
				if (output == "success")
					redirectUrl = "/login/otpVerification";
			}
		}
		else {
			UserDetails userDetails = (UserDetails) authentication.getPrincipal();
			String username = userDetails.getUsername();
			User user = userRepo.findByEmail(username);
			String output = userService.generateOtp(user);
			if (output == "success")
				redirectUrl = "/login/otpVerification";
		}
		new DefaultRedirectStrategy().sendRedirect(request, response, redirectUrl);
	}

}
