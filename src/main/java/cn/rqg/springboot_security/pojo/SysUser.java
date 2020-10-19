package cn.rqg.springboot_security.pojo;

import lombok.Data;
import java.io.Serializable;

@Data
public class SysUser implements Serializable {
    private int id;
    private String username;
    private String old_password;
    private String new_password;
    private String password;
}
