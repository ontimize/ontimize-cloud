package com.ontimize.cloud.security.centralized;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Collection;

import com.ontimize.jee.common.exceptions.OntimizeJEERuntimeException;
import com.ontimize.jee.server.security.authorization.ISecurityAuthorizator;
import com.ontimize.jee.server.security.authorization.Role;

public class CentralizedSecurityAuthorizator implements ISecurityAuthorizator {

	private ICentralizedAuthProvider authInfo;

	@Override
	public boolean hasPermission(String permissionName, Collection<String> userRoles) {
		try {
			return this.authInfo.hasPermission(Base64.getEncoder().encodeToString(permissionName.getBytes("UTF-8")));
		} catch (UnsupportedEncodingException ex) {
			throw new OntimizeJEERuntimeException(ex);
		}
	}


	@Override
	public Role getRole(String roleName) {
		return null;
	}

	@Override
	public void invalidateCache() {
		// do nothing
	}

	public void setAuthInfo(ICentralizedAuthProvider authInfo) {
		this.authInfo = authInfo;
	}

	public ICentralizedAuthProvider getAuthInfo() {
		return this.authInfo;
	}

}
