package ru.avm.lib.security.acl;

import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import ru.avm.lib.common.CompaniesProxy;
import ru.avm.lib.common.dto.AuthUserDto;
import ru.avm.lib.security.acl.admin.AdminService;
import ru.avm.lib.security.acl.admin.AuthoritiesProxy;
import ru.avm.lib.security.acl.admin.UpdateHierarchyListener;

import javax.sql.DataSource;

@RequiredArgsConstructor

@Configuration
@EnableMethodSecurity
public class SecurityAclConfig {

    @Value("${spring.application.name}")
    private String applicationName;
    private final CompaniesProxy companiesProxy;

    private final AuthoritiesProxy authoritiesProxy;
    private final RabbitTemplate rabbitTemplate;
    private final DataSource dataSource;
    private final AuthUserDto serviceUser;
    private static final String ACL_CACHE_NAME_SUFFIX = "AclCache";

    public String aclCacheName() {
        return applicationName + ACL_CACHE_NAME_SUFFIX;
    }

    @Bean
    public AdminService adminService(JdbcMutableAclService aclService, PermissionEvaluator permissionEvaluator) {
        return new AdminService(
                aclService,
                rabbitTemplate,
                companiesProxy,
                authoritiesProxy,
                serviceUser.toBuilder().authority("ROLE_ADMIN").build(),
                permissionEvaluator);
    }

    @Bean
    public UpdateHierarchyListener updateHierarchyListener(AdminService adminService) {
        return new UpdateHierarchyListener(adminService);
    }

    @Bean
    public PermissionEvaluator permissionEvaluator() {
        return new AclPermissionEvaluator(aclService());
    }

    @Bean
    public MethodSecurityExpressionHandler expressionHandler(PermissionEvaluator permissionEvaluator) {
        var expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(permissionEvaluator);
        return expressionHandler;
    }

    @Bean
    public AclAuthorizationStrategy aclAuthorizationStrategy() {
        return new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Bean
    public PermissionGrantingStrategy permissionGrantingStrategy() {
        val consoleAuditLogger = new ConsoleAuditLogger();
        return new DefaultPermissionGrantingStrategy(consoleAuditLogger);
    }

    @Bean
    public LookupStrategy lookupStrategy() {
        val lookupStrategy = new BasicLookupStrategy(dataSource, aclCache(), aclAuthorizationStrategy(),
                new ConsoleAuditLogger());
        lookupStrategy.setPermissionFactory(new DefaultPermissionFactory(SpecialPermission.class));
        return lookupStrategy;
    }

    @Bean
    public CacheManager cacheManager() {
        return new ConcurrentMapCacheManager(aclCacheName());
    }

    @Bean
    public AclCache aclCache() {
        Cache springCache = cacheManager().getCache(aclCacheName());
        assert springCache != null;
        return new SpringCacheBasedAclCache(springCache, permissionGrantingStrategy(), aclAuthorizationStrategy());
    }

    @Bean
    public JdbcMutableAclService aclService() {
        val service = new JdbcMutableAclService(dataSource, lookupStrategy(), aclCache());
//        service.setAclClassIdSupported(true);

        service.setSidIdentityQuery("select currval(pg_get_serial_sequence('acl_sid', 'id'))");
        service.setClassIdentityQuery("select currval(pg_get_serial_sequence('acl_class', 'id'))");

        return service;
    }
}
