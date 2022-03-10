package ru.avm.security.acl.admin;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class AclAlias {
    String aclType;
    Boolean withHierarchy;
    String aclHierarchyType;
}
