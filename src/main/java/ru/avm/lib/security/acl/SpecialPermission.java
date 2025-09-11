package ru.avm.lib.security.acl;

import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.Permission;

public class SpecialPermission extends BasePermission {

    public static final Permission SPECIAL = new SpecialPermission(1 << 5, 'S'); // 32

    protected SpecialPermission(int mask) {
        super(mask);
    }

    protected SpecialPermission(int mask, char code) {
        super(mask, code);
    }
}
