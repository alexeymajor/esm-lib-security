package ru.avm.lib.security.acl.admin;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import ru.avm.lib.common.CompaniesProxy;
import ru.avm.lib.common.dto.AuthUserDto;
import ru.avm.lib.common.dto.AuthorityDto;
import ru.avm.lib.security.TrustAuthenticationToken;
import ru.avm.lib.security.acl.SpecialPermission;
import ru.avm.lib.security.acl.admin.dto.AccessDto;

import java.io.Serializable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@RequiredArgsConstructor

@Slf4j
public class AdminService {

    private final MutableAclService aclService;

    private final RabbitTemplate rabbitTemplate;

    private final CompaniesProxy companiesProxy;
    private final AuthoritiesProxy authoritiesProxy;

    @Getter
    private final AclPermissionEvaluator aclPermissionEvaluator;

    @Getter
    private final Permission specialPermission = SpecialPermission.SPECIAL;

    private static final Set<AclAlias> typeAlias = ConcurrentHashMap.newKeySet();

    public void registerAlias(AclAlias type) {
        typeAlias.add(type);
    }

    public AccessDto getPermissions(String type, Serializable targetId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        return AccessDto.builder()
                .create(aclPermissionEvaluator.hasPermission(authentication, targetId, type, BasePermission.CREATE))
                .read(aclPermissionEvaluator.hasPermission(authentication, targetId, type, BasePermission.READ))
                .write(aclPermissionEvaluator.hasPermission(authentication, targetId, type, BasePermission.WRITE))
                .delete(aclPermissionEvaluator.hasPermission(authentication, targetId, type, BasePermission.DELETE))
                .special(aclPermissionEvaluator.hasPermission(authentication, targetId, type, SpecialPermission.SPECIAL))
                .administration(aclPermissionEvaluator.hasPermission(authentication, targetId, type, BasePermission.ADMINISTRATION))
                .build();
    }

    public boolean checkPermission(Object domainObject, Object permission) {
        val auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return false;
        return aclPermissionEvaluator.hasPermission(auth, domainObject, permission);
    }

    @SneakyThrows
    private Sid getCurrentSid() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!authentication.isAuthenticated()) {
            throw new Exception("principal not authenticated");
        }
        return new PrincipalSid(authentication.getName());
    }

    public Map<Sid, AccessDto> getAces(@PathVariable String type, @PathVariable Serializable identifier) {
        val oi = new ObjectIdentityImpl(type, identifier);
        val acl = aclService.readAclById(oi);

        return acl.getEntries().stream().collect(HashMap::new,
                (map, entry) -> map.merge(entry.getSid(), AdminUtils.toAccessDto(entry), AdminUtils::mergeAccess),
                (map1, map2) -> map2.forEach((sid, accessDto) -> map1.merge(sid, accessDto, AdminUtils::mergeAccess)));
    }

    public Sid findSid(String sid) {
        if (sid.startsWith("ROLE_") || sid.startsWith("SCOPE_")) {
            return new GrantedAuthoritySid(sid);
        }
        return new PrincipalSid(sid);
    }

    private MutableAcl getAcl(String type, Serializable entity) {
        val identity = new ObjectIdentityImpl(type, entity);
        return getAcl(identity);
    }

    private MutableAcl aclOf(ObjectIdentity identity) {
        try {
            return (MutableAcl) aclService.readAclById(identity);
        } catch (NotFoundException e) {
            return aclService.createAcl(identity);
        }
    }

    private MutableAcl getAcl(ObjectIdentity identity) {
        MutableAcl acl;
        try {
            acl = (MutableAcl) aclService.readAclById(identity);
        } catch (NotFoundException e) {
            acl = aclService.createAcl(identity);
        }

        if (!Long.valueOf(0).equals(identity.getIdentifier()) && acl.getParentAcl() == null) {
            val parentIdentity = new ObjectIdentityImpl(identity.getType(), 0);
            Acl parentAcl;
            try {
                parentAcl = aclService.readAclById(parentIdentity);
            } catch (NotFoundException e1) {
                parentAcl = aclService.createAcl(parentIdentity);
            }
            acl.setParent(parentAcl);
        }

        return acl;
    }

    @SuppressWarnings("unused")
    public void createAcl(Serializable entity, Serializable parent, Consumer<MutableAcl> aclConsumer) {
        createAcl(new ObjectIdentityImpl(entity), new ObjectIdentityImpl(parent), aclConsumer);
    }

    public void createAcl(Serializable entity, Serializable parent) {
        createAcl(new ObjectIdentityImpl(entity), new ObjectIdentityImpl(parent), acl -> {
        });
    }

    public void createAcl(ObjectIdentity entity, ObjectIdentity parent, Consumer<MutableAcl> aclConsumer) {
        val acl = aclOf(entity);
        val parentAcl = aclOf(parent);
        acl.setParent(parentAcl);
        acl.setOwner(getCurrentSid());
        acl.setEntriesInheriting(true);
        aclConsumer.accept(acl);
        try {
            aclService.updateAcl(acl);
        } catch (NotFoundException e) {
            log.error("create acl", e);
        }
    }

    public void editAcl(Serializable entity, Consumer<MutableAcl> aclConsumer) {
        val acl = (MutableAcl) aclService.readAclById(new ObjectIdentityImpl(entity));
        aclConsumer.accept(acl);
        aclService.updateAcl(acl);
    }

    @SuppressWarnings("unused")
    public void deleteAce(Serializable entity, Sid sid, Permission permission) {
        val acl = (MutableAcl) aclService.readAclById(new ObjectIdentityImpl(entity));
        for (int i = acl.getEntries().size() - 1; i >= 0; i--) {
            val ace = acl.getEntries().get(i);
            if (ace.getSid().equals(sid) && permission.equals(ace.getPermission())) {
                acl.deleteAce(i);
            }
        }
        aclService.updateAcl(acl);
    }

    public void updateAcl(Serializable entity) {
        val acl = (MutableAcl) aclService.readAclById(new ObjectIdentityImpl(entity));
        val parent = aclService.readAclById(new ObjectIdentityImpl(entity.getClass().getName(), 0L));
        if (acl.getParentAcl() == null || !acl.getParentAcl().equals(parent)) {
            acl.setParent(parent);
            aclService.updateAcl(acl);
        }
    }

    public void updateAcl(Serializable entity, Serializable parentEntity, Consumer<MutableAcl> aclConsumer) {
        val acl = (MutableAcl) aclService.readAclById(new ObjectIdentityImpl(entity));
        val parent = aclService.readAclById(new ObjectIdentityImpl(parentEntity));
        if (acl.getParentAcl() == null || !acl.getParentAcl().equals(parent)) {
            acl.setParent(parent);
        }
        aclConsumer.accept(acl);
        aclService.updateAcl(acl);
    }

    public void updateAcl(Serializable entity, Serializable parentEntity) {
        val acl = (MutableAcl) aclService.readAclById(new ObjectIdentityImpl(entity));
        val parent = aclService.readAclById(new ObjectIdentityImpl(parentEntity));
        if (acl.getParentAcl() == null || !acl.getParentAcl().equals(parent)) {
            acl.setParent(parent);
            aclService.updateAcl(acl);
        }
    }

    @Transactional
    public void updatePermissions(String sid, String type, Serializable targetId, AccessDto permissions) {
        val sidObject = findSid(sid);

        val acl = getAcl(type, targetId);


        val res = new AccessDto();

        for (int i = acl.getEntries().size() - 1; i >= 0; i--) {
            if (acl.getEntries().get(i).getSid().equals(sidObject)) {
                if (BasePermission.READ.equals(acl.getEntries().get(i).getPermission())) {
                    if (!permissions.isRead()) {
                        acl.deleteAce(i);
                        continue;
                    }
                    res.setRead(true);
                    continue;
                }
                if (BasePermission.CREATE.equals(acl.getEntries().get(i).getPermission())) {
                    if (!permissions.isCreate()) {
                        acl.deleteAce(i);
                        continue;
                    }
                    res.setCreate(true);
                    continue;
                }
                if (BasePermission.WRITE.equals(acl.getEntries().get(i).getPermission())) {
                    if (!permissions.isWrite()) {
                        acl.deleteAce(i);
                        continue;
                    }
                    res.setWrite(true);
                    continue;
                }
                if (BasePermission.DELETE.equals(acl.getEntries().get(i).getPermission())) {
                    if (!permissions.isDelete()) {
                        acl.deleteAce(i);
                        continue;
                    }
                    res.setDelete(true);
                    continue;
                }

                if (SpecialPermission.SPECIAL.equals(acl.getEntries().get(i).getPermission())) {
                    if (!permissions.isSpecial()) {
                        acl.deleteAce(i);
                        continue;
                    }
                    res.setSpecial(true);
                    continue;
                }

                if (BasePermission.ADMINISTRATION.equals(acl.getEntries().get(i).getPermission())) {
                    if (!permissions.isAdministration()) {
                        acl.deleteAce(i);
                        continue;
                    }
                    res.setAdministration(true);
                }
            }
        }

        if (permissions.isRead() && !res.isRead()) {
            acl.insertAce(acl.getEntries().size(), BasePermission.READ, sidObject, true);
        }

        if (permissions.isCreate() && !res.isCreate()) {
            acl.insertAce(acl.getEntries().size(), BasePermission.CREATE, sidObject, true);
        }

        if (permissions.isWrite() && !res.isWrite()) {
            acl.insertAce(acl.getEntries().size(), BasePermission.WRITE, sidObject, true);
        }

        if (permissions.isDelete() && !res.isDelete()) {
            acl.insertAce(acl.getEntries().size(), BasePermission.DELETE, sidObject, true);
        }

        if (permissions.isSpecial() && !res.isSpecial()) {
            acl.insertAce(acl.getEntries().size(), SpecialPermission.SPECIAL, sidObject, true);
        }

        if (permissions.isAdministration() && !res.isAdministration()) {
            acl.insertAce(acl.getEntries().size(), BasePermission.ADMINISTRATION, sidObject, true);
        }

        aclService.updateAcl(acl);

        rabbitTemplate.convertAndSend("sales.admin." + type + "." + targetId + "." + sid, permissions);

    }

    private void fill(Acl acl, Permission permission, List<Sid> list) {
        val sids = acl.getEntries().stream()
                .filter(ace -> ace.getPermission().equals(permission))
                .map(AccessControlEntry::getSid)
                .toList();
        list.addAll(sids);
        val parent = acl.getParentAcl();
        if (parent != null) {
            fill(parent, permission, list);
        }
    }

    public Collection<String> getSidsWithPermission(ObjectIdentity identity, Permission permission) {
        val acl = aclService.readAclById(identity);
        val list = acl.getEntries().stream()
                .filter(ace -> ace.getPermission().equals(permission))
                .map(AccessControlEntry::getSid)
                .collect(Collectors.toCollection(ArrayList::new));
        val parent = acl.getParentAcl();
        if (parent != null) {
            fill(parent, permission, list);
        }

        val principals = list.stream().filter(sid -> sid instanceof GrantedAuthoritySid)
                .map(sid -> ((GrantedAuthoritySid) sid).getGrantedAuthority())
                .map(authoritiesProxy::principalsByAuthority)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());

        principals.addAll(list.stream().filter(sid -> sid instanceof PrincipalSid)
                .map(sid -> ((PrincipalSid) sid).getPrincipal())
                .collect(Collectors.toSet()));

        return principals;
    }

    private MutableAcl getAclNoParentCreate(String type, Serializable id) {
        val identity = new ObjectIdentityImpl(type, id);
        try {
            return (MutableAcl) aclService.readAclById(identity);
        } catch (NotFoundException e) {
            return aclService.createAcl(identity);
        }

    }

    public void updateParent(String type, Long id, Long parentId) {
        val acl = getAclNoParentCreate(type, id);
        val parent = getAclNoParentCreate(type, parentId);

        acl.setParent(parent);
        aclService.updateAcl(acl);
    }

    @Transactional
    public void updateHierarchy() {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {

            val systemUser = AuthUserDto.builder()
                    .id(0L)
                    .sid("system")
                    .authorities(Set.of(AuthorityDto.builder().authority("ROLE_ADMIN").build()))
                    .build();

            SecurityContextHolder.getContext().setAuthentication(new TrustAuthenticationToken(systemUser));
        }

        val aclTypes = typeAlias.stream()
                .filter(AclAlias::getWithHierarchy)
//                .map(AclAlias::getAclHierarchyType)
                .collect(Collectors.toSet());

        companiesProxy.findAll().forEach(company ->
                aclTypes.forEach(aclType -> {
                    try {
                        aclType.getOnUpdate().accept(company);
                    } catch (Exception e) {
                        log.warn("update company exception ", e);
                    }
                    updateParent(aclType.getAclHierarchyType(), company.id(),
                            Optional.ofNullable(company.parentId()).orElse(0L));
                }));
    }

}
