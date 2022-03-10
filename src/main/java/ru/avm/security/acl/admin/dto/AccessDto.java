package ru.avm.security.acl.admin.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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
    boolean administration;
}
