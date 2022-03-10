package ru.avm.security.acl.admin.dto;

import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;


@Jacksonized
@Builder
@Value
public class SidAccessDto {
    String sid;
    Boolean principal;
    Boolean create;
    Boolean read;
    Boolean write;
    Boolean delete;
    Boolean special;
    Boolean administration;
}
