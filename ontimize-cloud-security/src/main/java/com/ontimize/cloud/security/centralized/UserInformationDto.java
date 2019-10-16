package com.ontimize.cloud.security.centralized;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.ontimize.jee.common.services.user.UserInformation;

public class UserInformationDto {

	private static final long	serialVersionUID	= 1L;

	private Map<Object, Object>	otherData;
	private String				username;
	private Collection<String>	authorities;
	private boolean				accountNonExpired;
	private boolean				accountNonLocked;
	private boolean				credentialsNonExpired;
	private boolean				enabled;
	private Map<String, String>	clientPermissions;

	public UserInformationDto() {
		super();
	}

	public UserInformationDto(String username, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<String> grantedAuthorities, Map<String, String> clientPermissions) {
		this.username = username;
		this.enabled = enabled;
		this.accountNonExpired = accountNonExpired;
		this.credentialsNonExpired = credentialsNonExpired;
		this.accountNonLocked = accountNonLocked;
		this.authorities = grantedAuthorities;
		this.clientPermissions = clientPermissions;
	}

	public void addOtherData(Object key, Object value) {
		this.otherData.put(key, value);
	}

	public Object removeOtherData(Object key) {
		return this.otherData.remove(key);
	}

	public Map<Object, Object> getOtherData() {
		return this.otherData;
	}

	public void setOtherData(Map<Object, Object> otherData) {
		this.otherData = otherData;
	}

	public Collection<String> getAuthorities() {
		return this.authorities;
	}

	public void setAuthorities(Collection<String> authorities) {
		this.authorities = authorities;
	}

	public String getLogin() {
		return this.getUsername();
	}

	public void setLogin(String login) {
		this.setUsername(login);
	}

	public String getUsername() {
		return this.username;
	}

	public void setUsername(String username) {
		this.username = username;
	}


	public boolean isEnabled() {
		return this.enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}


	public boolean isAccountNonExpired() {
		return this.accountNonExpired;
	}

	public void setAccountNonExpired(boolean accountNonExpired) {
		this.accountNonExpired = accountNonExpired;
	}


	public boolean isAccountNonLocked() {
		return this.accountNonLocked;
	}

	public void setAccountNonLocked(boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}


	public boolean isCredentialsNonExpired() {
		return this.credentialsNonExpired;
	}

	public void setCredentialsNonExpired(boolean credentialsNonExpired) {
		this.credentialsNonExpired = credentialsNonExpired;
	}

	public Map<String, String> getClientPermissions() {
		return this.clientPermissions;
	}

	public void setClientPermissions(Map<String, String> clientPermissions) {
		this.clientPermissions = clientPermissions;
	}


	@Override
	public boolean equals(Object rhs) {
		if (rhs instanceof UserInformationDto) {
			return this.username.equals(((UserInformationDto) rhs).username);
		}
		return false;
	}


	@Override
	public int hashCode() {
		return this.username.hashCode();
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString()).append(": ");
		sb.append("Username: ").append(this.username).append("; ");
		sb.append("Enabled: ").append(this.enabled).append("; ");
		sb.append("AccountNonExpired: ").append(this.accountNonExpired).append("; ");
		sb.append("credentialsNonExpired: ").append(this.credentialsNonExpired).append("; ");
		sb.append("AccountNonLocked: ").append(this.accountNonLocked).append("; ");

		if (!this.authorities.isEmpty()) {
			sb.append("Granted Authorities: ");

			boolean first = true;
			for (String auth : this.authorities) {
				if (!first) {
					sb.append(",");
				}
				first = false;

				sb.append(auth);
			}
		} else {
			sb.append("Not granted any authorities");
		}

		return sb.toString();
	}

	public UserInformation toOntimizeUserInformation() {
		Collection<? extends GrantedAuthority> grantedAuthorities = this.authorities.stream().map(x -> new SimpleGrantedAuthority(x)).collect(Collectors.toList());
		UserInformation userInformation = new UserInformation(this.username, null, this.enabled, this.accountNonExpired, this.credentialsNonExpired, this.accountNonLocked,
				grantedAuthorities, this.clientPermissions);
		return userInformation;
	}

	public static UserInformationDto toDto(UserInformation res) {
		Collection<String> grantedAuthorities = res.getAuthorities().stream().map(x -> x.getAuthority()).collect(Collectors.toList());
		UserInformationDto userInformationDto = new UserInformationDto(res.getUsername(), res.isEnabled(), res.isAccountNonExpired(), res.isCredentialsNonExpired(),
				res.isAccountNonLocked(), grantedAuthorities, (Map<String, String>) res.getClientPermissions());
		return userInformationDto;
	}
}
