package ru.avm.lib.security.acl;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;


//TODO когда в идее сделают
@Getter
@Setter
public class CustomMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

    private Object filterObject;
    private Object returnObject;
    private Object target;

    public CustomMethodSecurityExpressionRoot(Authentication authentication) {
        super(authentication);
    }

    @SuppressWarnings("unused")
    public boolean isServiceScope() {
        return hasAuthority("SCOPE_SERVICE");
    }

    @Override
    public Object getThis() {
        return target;
    }
}
