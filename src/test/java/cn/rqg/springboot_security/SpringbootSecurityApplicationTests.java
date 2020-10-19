package cn.rqg.springboot_security;

import cn.rqg.springboot_security.pojo.SysAuthority;
import cn.rqg.springboot_security.pojo.SysUser;
import cn.rqg.springboot_security.service.SysAuthoritiesService;
import cn.rqg.springboot_security.service.SysUserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
class SpringbootSecurityApplicationTests {
    @Autowired
    SysUserService sysUserService;
    @Autowired
    SysAuthoritiesService sysAuthoritiesService;
    @Test
    void userTest(){
        SysUser user = sysUserService.getUserByName("abc");
        System.out.println(user);
    }

    @Test
    void AuthorityTest(){
        List<SysAuthority> authorities = sysAuthoritiesService.getUserAuthorities("abc");
        System.out.println(authorities);
    }

}
