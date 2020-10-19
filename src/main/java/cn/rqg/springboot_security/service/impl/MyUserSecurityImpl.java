package cn.rqg.springboot_security.service.impl;

import cn.rqg.springboot_security.mapper.SysUserMapper;
import cn.rqg.springboot_security.pojo.SysAuthority;
import cn.rqg.springboot_security.pojo.SysUser;
import cn.rqg.springboot_security.service.SysAuthoritiesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class MyUserSecurityImpl implements UserDetailsService {
    @Autowired
    SysUserMapper sysUserMapper;
    @Autowired
    SysAuthoritiesService sysAuthoritiesService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser sysUser = sysUserMapper.findByUsername(username);
        List<SysAuthority> userAuthorities = sysAuthoritiesService.getUserAuthorities(username);
        StringBuilder authorityList = new StringBuilder();
        for (SysAuthority sysAuthority:userAuthorities){
            authorityList.append(sysAuthority.getRoles());
        }
        //User user = new User(sysUser.getUsername(),sysUser.getPassword(),AuthorityUtils.commaSeparatedStringToAuthorityList(authorityList.toString()));
        String password = new BCryptPasswordEncoder().encode(sysUser.getPassword());
        User user = new User(sysUser.getUsername(),password,AuthorityUtils.commaSeparatedStringToAuthorityList(authorityList.toString()));
        return user;
    }
}
