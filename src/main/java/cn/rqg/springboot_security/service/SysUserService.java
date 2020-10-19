package cn.rqg.springboot_security.service;

import cn.rqg.springboot_security.pojo.SysUser;

public interface SysUserService {
    SysUser getUserByName(String username);
}
