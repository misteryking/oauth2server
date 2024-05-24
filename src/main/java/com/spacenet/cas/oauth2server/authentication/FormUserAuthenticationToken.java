package com.spacenet.cas.oauth2server.authentication;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

//@JsonDeserialize
//@JsonIgnoreProperties(ignoreUnknown = true)
public class FormUserAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final Object principal;

	private Object credentials;
	
	private Object systemId;

	/**
	 * This constructor can be safely used by any code that wishes to create a
	 * <code>UsernamePasswordAuthenticationToken</code>, as the {@link #isAuthenticated()}
	 * will return <code>false</code>.
	 *
	 */
	
	public FormUserAuthenticationToken() {
		super(null);
		this.principal = new Object();
	}
	
	public FormUserAuthenticationToken(Object principal, Object credentials, Object systemId) {
		super(null);
		this.principal = principal;
		this.credentials = credentials;
		this.systemId = systemId;
		setAuthenticated(false);
	}

	/**
	 * This constructor should only be used by <code>AuthenticationManager</code> or
	 * <code>AuthenticationProvider</code> implementations that are satisfied with
	 * producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
	 * authentication token.
	 * @param principal
	 * @param credentials
	 * @param authorities
	 */
	public FormUserAuthenticationToken(Object principal, Object credentials, Object systemId,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		this.systemId = systemId;
		super.setAuthenticated(true); // must use super, as we override
	}

	/**
	 * This factory method can be safely used by any code that wishes to create a
	 * unauthenticated <code>UsernamePasswordAuthenticationToken</code>.
	 * @param principal
	 * @param credentials
	 * @return UsernamePasswordAuthenticationToken with false isAuthenticated() result
	 *
	 * @since 5.7
	 */
	public static FormUserAuthenticationToken unauthenticated(Object principal, Object credentials, Object systemId) {
		return new FormUserAuthenticationToken(principal, credentials, systemId);
	}

	/**
	 * This factory method can be safely used by any code that wishes to create a
	 * authenticated <code>UsernamePasswordAuthenticationToken</code>.
	 * @param principal
	 * @param credentials
	 * @return UsernamePasswordAuthenticationToken with true isAuthenticated() result
	 *
	 * @since 5.7
	 */
	public static FormUserAuthenticationToken authenticated(Object principal, Object credentials, Object systemId,
			Collection<? extends GrantedAuthority> authorities) {
		return new FormUserAuthenticationToken(principal, credentials, systemId, authorities);
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}
	
	public Object getSystemId() {
		return this.systemId;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated,
				"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.credentials = null;
	}

}
