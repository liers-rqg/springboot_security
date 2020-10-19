package cn.rqg.springboot_security.service.impl;

import cn.rqg.springboot_security.mapper.SysUserMapper;
import cn.rqg.springboot_security.pojo.SysUser;
import cn.rqg.springboot_security.service.SysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SysUserServiceImpl implements SysUserService {
    @Autowired
    SysUserMapper sysUserMapper;
    @Override
    public SysUser getUserByName(String username) {
        SysUser sysUser = sysUserMapper.findByUsername(username);
        return sysUser;
    }
}
