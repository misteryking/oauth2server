package com.spacenet.cas.oauth2server.user;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Entity
@Table(name="PERMISSION")
public class Permission extends BaseIdEntity {

	private String name;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}