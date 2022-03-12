package ru.avm.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.val;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import ru.avm.common.dto.AuthUserDto;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class TrustAuthenticationFilter extends GenericFilterBean {

    private static final String userHeader = "X-Auth-User";
    private final ObjectMapper objectMapper;

    public TrustAuthenticationFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @SneakyThrows
    private void internalFilter(HttpServletRequest request) {
        val userBase64String = request.getHeader(userHeader);

        if (Strings.isBlank(userBase64String)) {
            return;
        }

        val userString = Base64.decodeBase64(userBase64String);
        val user = objectMapper.readValue(userString, AuthUserDto.class);
        val authentication = new TrustAuthenticationToken(user);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (SecurityContextHolder.getContext().getAuthentication() == null && request instanceof HttpServletRequest) {
            internalFilter((HttpServletRequest) request);
        }

        chain.doFilter(request, response);
    }
}
