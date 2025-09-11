package ru.avm.lib.security.acl.admin;

import lombok.SneakyThrows;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import ru.avm.lib.common.dto.CompanyDto;
import ru.avm.lib.security.acl.admin.dto.AccessDto;
import ru.avm.lib.security.acl.admin.dto.SidAccessDto;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

@RequestMapping("default")
public interface AclController {

    String getAclType();

    AdminService getAdminService();

    default void onHierarchyUpdate(CompanyDto company) {
    }

    default Boolean getWithHierarchy() {
        return !Objects.equals(getAclHierarchyType(), getAclType());
    }

    default String getAclHierarchyType() {
        return getAclType();
    }

    @Autowired
    default void register(AdminService adminService) {
        val types = AclAlias.builder()
                .withHierarchy(getWithHierarchy())
                .aclHierarchyType(getAclHierarchyType())
                .onUpdate(this::onHierarchyUpdate)
                .aclType(getAclType()).build();
        adminService.registerAlias(types);
    }

    private void checkAccess(Long targetId) {
        val authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("access denied");
        }

        val isAdmin = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));

        if (isAdmin) return;

        val aclAccess = getAdminService().getAclPermissionEvaluator()
                .hasPermission(authentication, targetId, getAclType(), BasePermission.ADMINISTRATION);
        if (!aclAccess) {
            throw new AccessDeniedException("access denied");
        }
    }

    @GetMapping("permissions")
    default AccessDto permissions() {
        return getAdminService().getPermissions(getAclType(), 0L);
    }

    @GetMapping("{id}/permissions")
    default AccessDto permissions(@PathVariable Long id) {
        return getAdminService().getPermissions(getAclType(), id);
    }

    @SneakyThrows
    @GetMapping("{id}/acl")
    default List<SidAccessDto> aclList(@PathVariable Long id) {

        checkAccess(id);

        try {
            return AdminUtils.convert(getAdminService().getAces(getAclType(), id));
        } catch (NotFoundException e) {
            return Collections.emptyList();
        }
    }

    @SneakyThrows
    @GetMapping("acl")
    default List<SidAccessDto> aclList() {
        return aclList(0L);
    }

    @SneakyThrows
    @PutMapping("{id}/acl/{sid}")
    default void updatePermissions(@PathVariable Long id, @PathVariable String sid, @RequestBody AccessDto accessDto) {
        checkAccess(id);
        getAdminService().updatePermissions(sid, getAclType(), id, accessDto);
    }

    @SneakyThrows
    @PutMapping("acl/{sid}")
    default void updatePermissions(@PathVariable String sid, @RequestBody AccessDto accessDto) {
        checkAccess(0L);
        getAdminService().updatePermissions(sid, getAclType(), 0L, accessDto);
    }

    @SneakyThrows
    @GetMapping("{id}/acl/{sid}")
    default SidAccessDto getPermissions(@PathVariable Long id, @PathVariable String sid) {
        checkAccess(id);
        val aces = getAdminService().getAces(getAclType(), id);

        Sid sidObj = new PrincipalSid(sid);
        AccessDto accessDto = aces.getOrDefault(sidObj, null);

        if (accessDto == null) {
            sidObj = new GrantedAuthoritySid(sid);
            accessDto = aces.getOrDefault(sidObj, null);
        }

        return SidAccessDto.builder()
                .sid(sid)
                .principal(sidObj instanceof PrincipalSid ? true : null)
                .create(accessDto.isCreate() ? true : null)
                .read(accessDto.isRead() ? true : null)
                .write(accessDto.isWrite() ? true : null)
                .delete(accessDto.isDelete() ? true : null)
                .special(accessDto.isSpecial() ? true : null)
                .administration(accessDto.isAdministration() ? true : null)
                .build();
    }

    @SneakyThrows
    @GetMapping("acl/{sid}")
    default SidAccessDto getPermissions(@PathVariable String sid) {
        return getPermissions(0L, sid);
    }

}
