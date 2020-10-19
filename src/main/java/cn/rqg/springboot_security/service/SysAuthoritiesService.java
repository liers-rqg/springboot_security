package cn.rqg.springboot_security.service;

import cn.rqg.springboot_security.pojo.SysAuthority;

import java.util.List;

public interface SysAuthoritiesService {
    List<SysAuthority> getUserAuthorities(String username);
}
