package ru.avm.lib.security.acl.admin;

import lombok.Builder;
import lombok.Value;
import ru.avm.lib.common.dto.CompanyDto;

import java.util.function.Consumer;

@Value
@Builder
public class AclAlias {
    String aclType;
    Boolean withHierarchy;
    String aclHierarchyType;
    Consumer<CompanyDto> onUpdate;
}
