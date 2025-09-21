package ru.avm.lib.security.acl.admin.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class AccessDto {
    boolean create;
    boolean read;
    boolean write;
    boolean delete;
    boolean special;
    @With
    boolean administration;
}
