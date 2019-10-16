package com.ontimize.cloud.security.centralized;

import com.ontimize.jee.common.exceptions.OntimizeJEEException;

public interface ICentralizedAuthProvider {

	UserInformationDto getUserInformation() throws OntimizeJEEException;

	Boolean hasPermission(String permissionName);

	String requestToken();

	void invalidateCache();
}
