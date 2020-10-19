package cn.rqg.springboot_security.mapper;

import cn.rqg.springboot_security.pojo.SysAuthority;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Mapper
@Repository
public interface SysAuthoritiesMapper {
    SysAuthority getUserAuthorities(String username);
}
