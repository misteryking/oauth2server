package com.spacenet.cas.oauth2server.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

//import com.spacenet.cas.oauth2server.dto.FormUserAuthenticationToken;
import com.spacenet.cas.oauth2server.user.User;
import com.spacenet.cas.oauth2server.user.UserRepository;

//WAS WORKING
@Component("customAuthenticationProvider")
public class AuthenticationProviderImpl implements AuthenticationProvider {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	@Qualifier("bCrypt")
	private PasswordEncoder passwordEncoderBCrypt;
	
	
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		//FormUserAuthenticationToken token = (FormUserAuthenticationToken) authentication;
		UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken)authentication;
		
        String userName = authentication.getName();
		String dicelo = authentication.getCredentials().toString();
		
		System.out.println("authenticate username " + userName + " " + dicelo //+  ", systemId " + token.getSystemId()
				);
		
		User user = userRepository.findByUsername(userName);

		if (user == null) {
			System.out.println("AuthenticationProviderImpl user not register");
				throw new UsernameNotFoundException("user not registed!");
		}
		new AccountStatusUserDetailsChecker().check(user);
		System.out.println("AuthenticationProviderImpl passed checker");
		
		if (passwordEncoderBCrypt.matches(dicelo, user.getPassword())) {
			System.out.println("AuthenticationProviderImpl success " + user.getAuthorities().size());
			//user.getAuthorities();
			//return new FormUserAuthenticationToken(userName, dicelo, token.getSystemId(), user.getAuthorities());
			return new UsernamePasswordAuthenticationToken(userName, dicelo, user.getAuthorities());
		}else {
			System.out.println("AuthenticationProviderImpl BadCredentials");
			throw new BadCredentialsException("Invalid username or password");
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		//return authentication.equals(FormUserAuthenticationToken.class);
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}
