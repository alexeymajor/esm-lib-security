package ru.avm.lib.security;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import ru.avm.lib.common.dto.AuthUserDto;

import java.util.Collection;

@EqualsAndHashCode
public class TrustAuthenticationToken implements Authentication {

    @Getter
    private final AuthUserDto principal;

    public TrustAuthenticationToken(AuthUserDto user) {
        principal = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return principal.authorities();
    }

    @Override
    public Object getCredentials() {
        return "[trust]";
    }

    @Override
    public Object getDetails() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return principal.sid();
    }
}
