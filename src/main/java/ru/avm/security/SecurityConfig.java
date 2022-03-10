package ru.avm.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.val;
import org.apache.commons.codec.binary.Base64;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import ru.avm.common.dto.AuthUserDto;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String userHeader = "X-Auth-User";
    private final ObjectMapper objectMapper;

    @Bean
    public AuthenticationConverter trustAuthenticationConverter() {
        //noinspection Convert2Lambda
        return new AuthenticationConverter() {
            @SneakyThrows
            @Override
            public Authentication convert(HttpServletRequest request) {
                val userBase64String = request.getHeader(userHeader);
                val userString = Base64.decodeBase64(userBase64String);
                val user = objectMapper.readValue(userString, AuthUserDto.class);
                return new TrustAuthenticationToken(user);
            }
        };
    }

    @Bean
    public AuthenticationManager trustAuthenticationManager() {
        return authentication -> authentication;
    }

    @Bean
    public AuthenticationFilter trustAuthenticationFilter() {
        AuthenticationFilter filter = new AuthenticationFilter(trustAuthenticationManager(), trustAuthenticationConverter());
        filter.setRequestMatcher(new RequestHeaderRequestMatcher(userHeader));
        filter.setSuccessHandler((request, response, authentication) -> {

        });
        filter.setFailureHandler((request, response, exception) -> response.setStatus(HttpServletResponse.SC_FORBIDDEN));
        return filter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/actuator/**").hasIpAddress("127.0.0.1")
                .antMatchers("**").permitAll()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
//                .requestCache().disable()
                .httpBasic().disable()
                .rememberMe().disable()
//                .anonymous().disable()
                .formLogin().disable()
                .logout().disable()
                .addFilterBefore(trustAuthenticationFilter(), AnonymousAuthenticationFilter.class)
                .csrf().disable()
        ;

        super.configure(http);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

}
