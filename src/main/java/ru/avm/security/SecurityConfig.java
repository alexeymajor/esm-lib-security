package ru.avm.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@RequiredArgsConstructor

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final ObjectMapper objectMapper;

    @SneakyThrows
    @Bean
    public TrustAuthenticationFilter trustAuthenticationFilter() {
        return new TrustAuthenticationFilter(objectMapper);
    }

    @Bean
    public TrustAuthenticationProvider trustAuthenticationProvider() {
        return new TrustAuthenticationProvider();
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
                .requestCache().disable()
                .headers().frameOptions().sameOrigin()
                .and()
                .httpBasic().disable()
                .rememberMe().disable()
                .formLogin().disable()
                .logout().disable()
                .anonymous().disable()
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
