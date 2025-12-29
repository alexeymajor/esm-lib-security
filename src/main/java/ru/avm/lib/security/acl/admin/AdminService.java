package ru.avm.lib.security.acl.admin;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.access.PermissionEvaluator;
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
import ru.avm.lib.security.TrustAuthenticationToken;
import ru.avm.lib.security.acl.admin.dto.AccessDto;
import ru.avm.lib.security.acl.admin.dto.AclRoot;

import java.io.Serializable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.springframework.security.acls.domain.BasePermission.*;
import static ru.avm.lib.security.acl.SpecialPermission.SPECIAL;

@RequiredArgsConstructor

@Slf4j
public class AdminService {

    private final MutableAclService aclService;

    private final RabbitTemplate rabbitTemplate;

    private final CompaniesProxy companiesProxy;
    private final AuthoritiesProxy authoritiesProxy;

    private final AuthUserDto serviceUser;

    @Getter
    private final PermissionEvaluator permissionEvaluator;

    @Getter
    private final Permission specialPermission = SPECIAL;

    private static final Set<AclAlias> typeAlias = ConcurrentHashMap.newKeySet();

    public void registerAlias(AclAlias type) {
        typeAlias.add(type);
    }

    public void authServiceUser() {
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            throw new IllegalStateException("already authenticated");
        }
        val authentication = new TrustAuthenticationToken(serviceUser);
        val securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    public AccessDto getPermissions(String type, Serializable targetId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        return AccessDto.builder()
                .create(permissionEvaluator.hasPermission(authentication, targetId, type, CREATE))
                .read(permissionEvaluator.hasPermission(authentication, targetId, type, READ))
                .write(permissionEvaluator.hasPermission(authentication, targetId, type, WRITE))
                .delete(permissionEvaluator.hasPermission(authentication, targetId, type, DELETE))
                .special(permissionEvaluator.hasPermission(authentication, targetId, type, SPECIAL))
                .administration(permissionEvaluator.hasPermission(authentication, targetId, type, ADMINISTRATION))
                .build();
    }

    public boolean checkPermission(Object domainObject, Object permission) {
        val auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return false;
        return permissionEvaluator.hasPermission(auth, domainObject, permission);
    }

    @SneakyThrows
    private Sid getCurrentSid() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!authentication.isAuthenticated()) {
            throw new Exception("principal not authenticated");
        }
        return new PrincipalSid(authentication.getName());
    }

    @Transactional
    public Map<Sid, AccessDto> getAces(@PathVariable String type, @PathVariable Serializable identifier) {
        val oi = new ObjectIdentityImpl(type, identifier);
        val acl = aclService.readAclById(oi);

        return acl.getEntries().stream().collect(HashMap::new,
                (map, entry) -> map.merge(entry.getSid(), AdminUtils.toAccessDto(entry), AdminUtils::mergeAccess),
                (map1, map2) -> map2.forEach((sid, accessDto) -> map1.merge(sid, accessDto, AdminUtils::mergeAccess)));
    }

    public Sid makeSid(String sid) {
        if (sid.startsWith("ROLE_") || sid.startsWith("SCOPE_")) {
            return new GrantedAuthoritySid(sid);
        }
        return new PrincipalSid(sid);
    }

    private MutableAcl aclOf(ObjectIdentity identity) {
        try {
            return (MutableAcl) aclService.readAclById(identity);
        } catch (NotFoundException e) {
            return aclService.createAcl(identity);
        }
    }

    private MutableAcl makeAcl(String type, Serializable entity, String parentType, Long parentId) {
        val identity = new ObjectIdentityImpl(type, entity);

        MutableAcl acl;
        try {
            acl = (MutableAcl) aclService.readAclById(identity);
        } catch (NotFoundException e) {
            acl = aclService.createAcl(identity);
        }

        val parentIdentity = new ObjectIdentityImpl(parentType, parentId);
        Acl parentAcl;
        try {
            parentAcl = aclService.readAclById(parentIdentity);
        } catch (NotFoundException e1) {
            parentAcl = aclService.createAcl(parentIdentity);
        }
        acl.setParent(parentAcl);

        return acl;
    }

    @Transactional
    public void createAcl(Serializable entity, Serializable parent, Consumer<MutableAcl> aclConsumer) {
        createAcl(new ObjectIdentityImpl(entity), new ObjectIdentityImpl(parent), aclConsumer);
    }

    @Transactional
    public void createAcl(Serializable entity, Serializable parent) {
        createAcl(new ObjectIdentityImpl(entity), new ObjectIdentityImpl(parent), acl -> {
        });
    }

    @Transactional
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

    @Transactional
    public void editAcl(Serializable entity, Consumer<MutableAcl> aclConsumer) {
        val acl = (MutableAcl) aclService.readAclById(new ObjectIdentityImpl(entity));
        aclConsumer.accept(acl);
        aclService.updateAcl(acl);
    }

    @Transactional
    public void updateAcl(Serializable entity) {
        val acl = (MutableAcl) aclService.readAclById(new ObjectIdentityImpl(entity));
        val parent = aclService.readAclById(new ObjectIdentityImpl(entity.getClass().getName(), 0L));
        if (acl.getParentAcl() == null || !acl.getParentAcl().equals(parent)) {
            acl.setParent(parent);
            aclService.updateAcl(acl);
        }
    }

    @Transactional
    public void updateAcl(Serializable entity, Serializable parentEntity, Consumer<MutableAcl> aclConsumer) {
        val acl = (MutableAcl) aclService.readAclById(new ObjectIdentityImpl(entity));
        val parent = aclService.readAclById(new ObjectIdentityImpl(parentEntity));
        if (acl.getParentAcl() == null || !acl.getParentAcl().equals(parent)) {
            acl.setParent(parent);
        }
        aclConsumer.accept(acl);
        aclService.updateAcl(acl);
    }

    @Transactional
    public void updateAcl(Serializable entity, Serializable parentEntity) {
        val acl = (MutableAcl) aclService.readAclById(new ObjectIdentityImpl(entity));
        if (parentEntity != null) {
            val parent = aclService.readAclById(new ObjectIdentityImpl(parentEntity));
            if (acl.getParentAcl() == null || !acl.getParentAcl().equals(parent)) {
                acl.setParent(parent);
                aclService.updateAcl(acl);
            }
        }
    }

    @Transactional
    public void updatePermissions(String sid, String type, Long id, AccessDto permissions) {
        updatePermissions(sid, type, id, AclRoot.class.getName(), 0L, permissions);
    }

    @Transactional
    public void updatePermissions(String sid, String type, Long id, String parentType, Long parentId, AccessDto permissions) {
        val sidObject = makeSid(sid);

        val acl = makeAcl(type, id, parentType, parentId);

        val res = new AccessDto();

        for (int i = acl.getEntries().size() - 1; i >= 0; i--) {
            val ace = acl.getEntries().get(i);
            if (!ace.getSid().equals(sidObject))
                continue;

            val permission = ace.getPermission();
            if (READ.equals(permission)) {
                if (!permissions.isRead()) acl.deleteAce(i);
                else res.setRead(true);
            } else if (CREATE.equals(permission)) {
                if (!permissions.isCreate()) acl.deleteAce(i);
                else res.setCreate(true);
            } else if (WRITE.equals(permission)) {
                if (!permissions.isWrite()) acl.deleteAce(i);
                else res.setWrite(true);
            } else if (DELETE.equals(permission)) {
                if (!permissions.isDelete()) acl.deleteAce(i);
                else res.setDelete(true);
            } else if (SPECIAL.equals(permission)) {
                if (!permissions.isSpecial()) acl.deleteAce(i);
                else res.setSpecial(true);
            } else if (ADMINISTRATION.equals(permission)) {
                if (!permissions.isAdministration()) acl.deleteAce(i);
                else res.setAdministration(true);
            }
        }

        if (permissions.isRead() != res.isRead()) {
            acl.insertAce(acl.getEntries().size(), READ, sidObject, true);
        }
        if (permissions.isCreate() != res.isCreate()) {
            acl.insertAce(acl.getEntries().size(), CREATE, sidObject, true);
        }
        if (permissions.isWrite() != res.isWrite()) {
            acl.insertAce(acl.getEntries().size(), WRITE, sidObject, true);
        }
        if (permissions.isDelete() != res.isDelete()) {
            acl.insertAce(acl.getEntries().size(), DELETE, sidObject, true);
        }
        if (permissions.isSpecial() != res.isSpecial()) {
            acl.insertAce(acl.getEntries().size(), SPECIAL, sidObject, true);
        }
        if (permissions.isAdministration() != res.isAdministration()) {
            acl.insertAce(acl.getEntries().size(), ADMINISTRATION, sidObject, true);
        }

        aclService.updateAcl(acl);

        rabbitTemplate.convertAndSend("sales.admin." + type + "." + id + "." + sid, permissions);
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

    @Transactional
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

    @Transactional
    public void updateParent(String type, Long id, Long parentId) {
        val acl = getAclNoParentCreate(type, id);
        val parent = getAclNoParentCreate(type, parentId);

        acl.setParent(parent);
        aclService.updateAcl(acl);
    }

    @Transactional
    public void updateHierarchy() {
        try {
            authServiceUser();
        } catch (Exception e) {
            log.warn("auth service user exception");
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
                    val parentId = Optional.ofNullable(company.parentId()).orElse(0L);
                    updateParent(aclType.getAclHierarchyType(), company.id(), parentId);
                }));
    }

}
