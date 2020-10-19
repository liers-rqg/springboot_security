package cn.rqg.springboot_security.mapper;

import cn.rqg.springboot_security.pojo.SysUser;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Mapper
@Repository
public interface SysUserMapper {
    SysUser findByUsername(String username);
}
