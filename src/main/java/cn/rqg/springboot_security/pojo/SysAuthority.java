package cn.rqg.springboot_security.pojo;

import lombok.Data;
import java.io.Serializable;

@Data
public class SysAuthority implements Serializable {
    private int id;
    private String username;
    private String roles;//必须ROLE_开头,全大写
}
