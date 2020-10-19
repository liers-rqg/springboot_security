package cn.rqg.springboot_security.service.impl;

import cn.rqg.springboot_security.mapper.SysAuthoritiesMapper;
import cn.rqg.springboot_security.pojo.SysAuthority;
import cn.rqg.springboot_security.service.SysAuthoritiesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;

@Service
public class SysAuthoritiesServiceImpl implements SysAuthoritiesService {
    @Autowired
    SysAuthoritiesMapper sysAuthoritiesMapper;
    @Override
    public List<SysAuthority> getUserAuthorities(String username) {
        SysAuthority userAuthorities = sysAuthoritiesMapper.getUserAuthorities(username);
        List<SysAuthority> sysAuthorityList = new ArrayList<>();
        sysAuthorityList.add(userAuthorities);
        return sysAuthorityList;
    }
}
