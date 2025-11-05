package ru.avm.lib.security.acl.admin.dto;

import lombok.Getter;

import java.io.Serializable;

public class AclRoot implements Serializable {
    @Getter
    final Long id = 0L;

    public static final AclRoot INSTANCE = new AclRoot();
}
