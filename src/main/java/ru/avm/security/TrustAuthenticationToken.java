package ru.avm.security;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import ru.avm.common.dto.AuthUserDto;

import java.util.Collection;
import java.util.stream.Collectors;

@EqualsAndHashCode
public class TrustAuthenticationToken implements Authentication {

    @Getter
    private final AuthUserDto principal;

    public TrustAuthenticationToken(AuthUserDto user) {
        principal = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return principal.getAuthorities().stream()
                .map(authorityDto -> (GrantedAuthority) authorityDto::getAuthority)
                .collect(Collectors.toList());
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
        return principal.getSid();
    }
}
