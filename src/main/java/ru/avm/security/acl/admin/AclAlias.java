package ru.avm.security.acl.admin;

import lombok.Builder;
import lombok.Value;
import ru.avm.common.dto.CompanyDto;

import java.util.function.Consumer;

@Value
@Builder
public class AclAlias {
    String aclType;
    Boolean withHierarchy;
    String aclHierarchyType;
    Consumer<CompanyDto> onUpdate;
}
