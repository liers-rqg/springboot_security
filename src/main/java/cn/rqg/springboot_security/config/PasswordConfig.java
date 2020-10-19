package cn.rqg.springboot_security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class PasswordConfig implements PasswordEncoder {
    @Override
    public String encode(CharSequence rawPassword) {
        return (String) rawPassword;
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        log.info("***密码验证结果==>"+passwordEncoder.matches(rawPassword, encodedPassword));
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
