package com.spacenet.cas.oauth2server.user;

import jakarta.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;


//@RepositoryRestResource(path="role")
@Transactional
public interface RoleRepo extends JpaRepository<Role, Long>{
	
	/*@RestResource(exported = false)
	@Override
	void delete(Long id);*/
	
	/*@RestResource(exported = false)
	@Override
	void delete(Role role);
	
	@RestResource(exported = false)
	@Override
	Role save(Role role);*/
}

