package ru.avm.security.acl.admin;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@FeignClient(value = "authorities-proxy", url = "${app.services.migration}")
public interface AuthoritiesProxy {

    @GetMapping("authorities/{authority}/principals")
    List<String> principalsByAuthority(@PathVariable String authority);

}
