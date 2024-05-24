package com.spacenet.cas.oauth2server.authentication;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

//import com.spacenet.cas.oauth2.service.LoginService;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class Signing {
	
	//@Autowired
	//private LoginService loginService;
	
	@RequestMapping("/index")
	public String index(HttpServletRequest request) {
		return "index";
	}
	
	@RequestMapping("/signin")
	public String showSignin(HttpServletRequest request) {
		String lastEx="";
		if ( request.getAttribute("SPRING_SECURITY_LAST_EXCEPTION") != null) {
			lastEx=request.getAttribute("SPRING_SECURITY_LAST_EXCEPTION").toString();
		}
		String men = "";
		if (request.getAttribute("authFailureHandler")!=null) {
		 men = request.getAttribute("authFailureHandler").toString();
		}
		if (request.getSession().getAttribute("authFailureHandler")!=null) {
			 men = request.getSession().getAttribute("authFailureHandler").toString();
			 request.setAttribute("authFailureHandler", men);
		}
		System.out.println("get entry point " + lastEx + " " + men );
				
		//return "../static/index.html";
		return "login";
	}
	
	@RequestMapping("/user/signinfail")
	public String showSigninfail(HttpServletRequest request) {
		String men = request.getAttribute("authFailureHandler").toString();
		System.out.println("post entry point " + men);
		return "login";
	}
	
	/*@PostMapping("/user/signin")
	public String postSignin(HttpServletRequest request) {
		//Map<String, String> param = (HashMap<String, String>()) request.getAttribute("param");
		String exc = "";
		if ( request.getAttribute("SPRING_SECURITY_LAST_EXCEPTION") != null) {
			request.getAttribute("SPRING_SECURITY_LAST_EXCEPTION").toString();
		}
		String men = "";
		if (request.getAttribute("authFailureHandler")!=null) {
		 men = request.getAttribute("authFailureHandler").toString();
		}
		System.out.println("post entry point " + exc + " " + men //request.getAttributeNames()
				);
		return "login";
	}*/
	
	@RequestMapping("/user/fail")
	public String fail() {
		return "userin";
	}
	
	@PostMapping("/hello")
	public String showSigninlo() {
		return "login.html";
	}
	
	//@RequestMapping(value="/userauth",method = RequestMethod.POST)
	@PostMapping("/user/signinNO")
	public String userauth(@RequestParam(value="username") String username, @RequestParam(value="password") String password) {
	//public String userauth(String username, String password) {
		System.out.println("POST Controller username " + username + " password " + password);
		boolean result = false;//loginService.login(username, password);
		System.out.println("resutl " + result);
		if (result) {
			return "userin";
		}else {
			return "login";
		}
	}
	
	@PostMapping("/hellopost")
	public String hello() {
		return "userin.html";
	}
}