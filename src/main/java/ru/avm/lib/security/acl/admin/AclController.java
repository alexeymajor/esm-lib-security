package ru.avm.lib.security.acl.admin;

import jakarta.servlet.http.HttpServletRequest;
import lombok.SneakyThrows;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
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

import static org.springframework.security.acls.domain.BasePermission.ADMINISTRATION;

@RequestMapping("default")
public interface AclController {

    String getAclType();

    default String chooseAclType(Long id) {
        if (targetIsAclRoot(id)) return getParentAclType();
        return getAclType();
    }

    default Long chooseAclId(Long id, HttpServletRequest request) {
        if (targetIsAclRoot(id)) return getParentId(request);
        return id;
    }

    default String getParentAclType() {
        return getAclType();
    }

    default Integer getParentParameterIndex() {
        return null;
    }

    @SneakyThrows
    default Long getParentId(HttpServletRequest request) {
        if (getParentParameterIndex() == null) return 0L;
        val parts = request.getServletPath().split("/");
        val parentParameterValue = parts[getParentParameterIndex()];
        return Long.parseLong(parentParameterValue);
    }

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

    private void checkAccess(Long id, HttpServletRequest request) {
        val authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated())
            throw new AccessDeniedException("access denied");

        val isAdmin = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));

        if (isAdmin) return;

        val targetId = chooseAclId(id, request);
        val targetType = chooseAclType(id);

        val aclAccess = getAdminService().getPermissionEvaluator()
                .hasPermission(authentication, targetId, targetType, ADMINISTRATION);
        if (!aclAccess) throw new AccessDeniedException("access denied");

    }

    @GetMapping("permissions")
    default AccessDto permissions(HttpServletRequest request) {
        val parentType = getParentAclType();
        val parentId = getParentId(request);
        return getAdminService().getPermissions(parentType, parentId);
    }

    @GetMapping("{id}/permissions")
    default AccessDto permissions(@PathVariable Long id, HttpServletRequest request) {
        if (id == 0L) {
            return permissions(request);
        }
        return getAdminService().getPermissions(chooseAclType(id), id);
    }

    @SneakyThrows
    @GetMapping("{id}/acl")
    default List<SidAccessDto> aclList(@PathVariable Long id, HttpServletRequest request) {
        checkAccess(id, request);
        try {
            val targetId = chooseAclId(id, request);
            val targetType = chooseAclType(id);
            val acesMap = getAdminService().getAces(targetType, targetId);
            return AdminUtils.convert(acesMap);
        } catch (NotFoundException e) {
            return Collections.emptyList();
        }
    }

    @SneakyThrows
    @GetMapping("acl")
    default List<SidAccessDto> aclList(HttpServletRequest request) {
        return aclList(0L, request);
    }

    @SneakyThrows
    @PutMapping("{id}/acl/{sid}")
    default void updatePermissions(HttpServletRequest request, @PathVariable Long id, @PathVariable String sid, @RequestBody AccessDto permissions) {
        if (targetIsAclRoot(id)) {
            updatePermissions(request, sid, permissions);
            return;
        }
        checkAccess(id, request);
        val parentId = getParentId(request);
        val parentType = getParentAclType();
        val type = chooseAclType(id);
        getAdminService().updatePermissions(sid, type, id, parentType, parentId, permissions);
    }

    @SneakyThrows
    @PutMapping("acl/{sid}")
    default void updatePermissions(HttpServletRequest request, @PathVariable String sid, @RequestBody AccessDto permissions) {
        checkAccess(0L, request);
        val parentType = getParentAclType();
        val parentId = getParentId(request);
        if (parentId > 0) {
            getAdminService().updatePermissions(sid, parentType, parentId, parentType, 0L, permissions);
            return;
        }
        getAdminService().updatePermissions(sid, parentType, 0L, permissions);
    }

    default boolean targetIsAclRoot(Long id) {
        return id == 0L;
    }

    @SneakyThrows
    @GetMapping("{id}/acl/{sid}")
    default SidAccessDto getPermissions(@PathVariable Long id, @PathVariable String sid, HttpServletRequest request) {
        checkAccess(id, request);

        val targetType = chooseAclType(id);
        val targetId = chooseAclId(id, request);
        val aces = getAdminService().getAces(targetType, targetId);

        Sid sidObj = new PrincipalSid(sid);
        AccessDto accessDto = aces.getOrDefault(sidObj, null);
        Boolean isPrincipal = true;

        if (accessDto == null) {
            sidObj = new GrantedAuthoritySid(sid);
            accessDto = aces.getOrDefault(sidObj, new AccessDto());
            isPrincipal = null;
        }

        return SidAccessDto.builder()
                .sid(sid)
                .principal(isPrincipal)
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
    default SidAccessDto getPermissions(@PathVariable String sid, HttpServletRequest request) {
        return getPermissions(0L, sid, request);
    }

}
