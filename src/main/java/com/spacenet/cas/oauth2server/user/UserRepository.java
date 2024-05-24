package com.spacenet.cas.oauth2server.user;

import jakarta.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;



@Repository
@Transactional
public interface UserRepository extends JpaRepository<User, Long> {
	User findByUsername(String username);
}