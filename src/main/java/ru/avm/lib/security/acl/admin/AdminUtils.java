package ru.avm.lib.security.acl.admin;

import lombok.experimental.UtilityClass;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Sid;
import ru.avm.lib.security.acl.SpecialPermission;
import ru.avm.lib.security.acl.admin.dto.AccessDto;
import ru.avm.lib.security.acl.admin.dto.SidAccessDto;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@UtilityClass
public class AdminUtils {

    public List<SidAccessDto> convert(Map<Sid, AccessDto> map) {
        return map.entrySet().stream().map(entry -> SidAccessDto.builder()
                .sid(getSidName(entry.getKey()))
                .principal(entry.getKey() instanceof PrincipalSid ? true : null)
                .create(entry.getValue().isCreate() ? true : null)
                .read(entry.getValue().isRead() ? true : null)
                .write(entry.getValue().isWrite() ? true : null)
                .delete(entry.getValue().isDelete() ? true : null)
                .special(entry.getValue().isSpecial() ? true : null)
                .administration(entry.getValue().isAdministration() ? true : null)
                .build()).collect(Collectors.toList());
    }

    public AccessDto mergeAccess(AccessDto accessDto1, AccessDto accessDto2) {
        return AccessDto.builder()
                .create(accessDto1.isCreate() || accessDto2.isCreate())
                .read(accessDto1.isRead() || accessDto2.isRead())
                .write(accessDto1.isWrite() || accessDto2.isWrite())
                .delete(accessDto1.isDelete() || accessDto2.isDelete())
                .special(accessDto1.isSpecial() || accessDto2.isSpecial())
                .administration(accessDto1.isAdministration() || accessDto2.isAdministration())
                .build();
    }

    public AccessDto toAccessDto(AccessControlEntry entry) {
        return AccessDto.builder()
                .create(BasePermission.CREATE.equals(entry.getPermission()))
                .read(BasePermission.READ.equals(entry.getPermission()))
                .write(BasePermission.WRITE.equals(entry.getPermission()))
                .delete(BasePermission.DELETE.equals(entry.getPermission()))
                .special(SpecialPermission.SPECIAL.equals(entry.getPermission()))
                .administration(BasePermission.ADMINISTRATION.equals(entry.getPermission()))
                .build();
    }

    public String getSidName(Sid sid) {
        if (sid instanceof GrantedAuthoritySid) {
            return ((GrantedAuthoritySid) sid).getGrantedAuthority();
        }
        return ((PrincipalSid) sid).getPrincipal();
    }

}
