# springboot_security
A simple example of SpringSecurity based on springboot
## 1 security原理介绍

security身份验证的核心是SecurityContextHolder其中包含一个SecurityContext对象，该对象中又包含一个身份验证对象（套娃？），身份验证对象包括principal：当使用用户名/密码验证时，通常是一个UserDetails实例；Credentials：用户凭证，通常是密码，在部分将在认证后清除；Authorities：用户权限。

![securitycontextholder](https://docs.spring.io/spring-security/site/docs/5.3.5.RELEASE/reference/html5/images/servlet/authentication/architecture/securitycontextholder.png)

其中用户权限有security内置的权限包括ROLE_ADMINISTRATOR等，这些权限都是通过UserDetailsService加载的。值得注意的是作为GrantedAuthority，如果过多会非常占用内存（Spring官网没有做出详细解释）。

在security中执行身份验证操作的是AuthenticationManager，通常是其中的一个实现类ProviderManager进行验证管理，它可以管理多个AuthenticationProvider，而每个AuthenticationProvider都可以执行特定的身份验证机制，例如使用用户名/密码验证时执行的就是DaoAuthenticationProvider。

比较常见的用户名/密码身份验证方式是表单登陆，执行原理如下图

![loginurlauthenticationentrypoint](https://docs.spring.io/spring-security/site/docs/5.3.5.RELEASE/reference/html5/images/servlet/authentication/unpwd/loginurlauthenticationentrypoint.png)

首先，用户向未授权的资源发出未经身份验证的请求，经过security拦截器内置的FilterSecurityInterceptor 时，拦截器抛出 AccessDeniedException 表示拒绝未经身份验证的请求。由于用户没有经过身份验证，ExceptionTranslationFilter 初始化 Start Authentication，并使用配置的 AuthenticationEntryPoint 重定向到登录页面。在大多数情况下，AuthenticationEntryPoint 是 loginlauthenttrypoint 的实例。

用户通过表单提交用户名和密码后就会经历以下验证流程：

![usernamepasswordauthenticationfilter](https://docs.spring.io/spring-security/site/docs/5.3.5.RELEASE/reference/html5/images/servlet/authentication/unpwd/usernamepasswordauthenticationfilter.png)

当用户提交他们的用户名和密码时，UsernamePasswordAuthenticationFilter 通过从 HttpServletRequest 中提取用户名和密码创建一个UsernamePasswordAuthenticationTokeUsernamePasswordAuthenticationToken 被传递到 AuthenticationManager 以进行身份验证。AuthenticationManager 的详细内容取决于用户信息的存储方式。

上述提到的加载权限的UserDetailsService 被 DaoAuthenticationProvider 用于检索用户名、密码和其他属性，以便对用户名和密码进行身份验证。Spring Security 提供了 UserDetailsService 的内存和 JDBC 实现。绝大多数情况下是从数据库中提取信息，因此需要复写load方法实现这一功能。最后给出身份认证的全过程流程：

![daoauthenticationprovider](https://docs.spring.io/spring-security/site/docs/5.3.5.RELEASE/reference/html5/images/servlet/authentication/unpwd/daoauthenticationprovider.png)



## 2 利用UserDetailsService的数据库操作的自定义案例

### 2.1 前端页面和环境配置

#### 2.1.1 环境配置

配置security前SpringBoot中需要引入相应的依赖，其中包括数据库（这里选用Mybatis数据库）和security本身。为了更方便的执行前端操作还需要引入Thymeleaf模板引擎，在yml配置文件中对datasource，mybatis和thymeleaf进行配置。该项目的端口号为8100。

```yaml
#启动端口号
server:
  port: 8100

spring:
  #thymeleaf配置
  thymeleaf:
    cache: false

  #数据库配置
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql:///learn_1?serverTimezone=Asia/Shanghai
    password: 123321
    username: root
    type: org.springframework.jdbc.datasource.DriverManagerDataSource

mybatis:
  mapper-locations: classpath:mapper/*.xml
  type-aliases-package: cn.rqg.springboot_security.pojo
```



#### 2.1.2 前端页面

前端页面引入了layui框架（为了好看）和js框架（没啥用）以及模板引擎th，如下：

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Security测试登录页</title>
    <!-- Jquery -->
    <script type="text/javascript" src="../static/js/jquery.js" th:src="@{/js/jquery.js}"></script>

    <!-- Layui -->
    <link rel="stylesheet" href="../static/layui/css/layui.css" th:href="@{/layui/css/layui.css}" type="text/css">
    <script type="text/javascript" src="../static/layui/layui.js" th:src="@{/layui/layui.js}" charset="utf-8"></script>
    <style>
        /*上下左右居中*/
        .main {
            display: flex;
            justify-content: center;
            align-items: center;
            margin-top: 150px;
        }
    </style>
</head>
```

前端页面中编辑form表单，根据security要求，表单提交的路径默认为"/login"，提交方式必须为"post"，这些可以在之后的后台配置类中修改。建立表单如下

```html
<div class="main">
    <!--用户登陆表单-->
    <form class="layui-form layui-form-pane" th:action="@{/login}" method="post">
        <!--标题栏-->
        <div class="layui-form-item">
            <h1 style="text-align: center">Security登录测试</h1>
        </div>
        <!--回写错误信息-->
        <div th:if="${param.error}">

        </div>
        <!--用户名-->
        <div class="layui-form-item">
            <label class="layui-form-label">用户名<i class="layui-icon layui-icon-username"></i></label>
            <div class="layui-input-block">
                <input class="layui-input" type="text" id="username" name="username" placeholder="请输入用户名">
            </div>
        </div>
        <!--密码-->
        <div class="layui-form-item">
            <label class="layui-form-label">密码<i class="layui-icon layui-icon-password"></i></label>
            <div class="layui-input-block">
                <input class="layui-input" type="text" id="password" name="password" placeholder="请输入密码">
            </div>
        </div>
        <!--提交-->
        <div class="layui-form-item">
            <div class="layui-input-block">
                <input class="layui-btn" style="margin-left: -50px;margin-right: 50px;" type="submit" value="登录">
            </div>
        </div>

    </form>
</div>
</body>
```

表单建立完成后需要继续编写另一个页面index，作为需要授权才能访问的页面。页面较为简单，编写如下：

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>成功页面</title>
</head>
<body>
security测试成功
</body>
</html>
```

在前端页面编写过程中需要注意的两点，一是thymeleaf模板引擎默认前端页面路径在项目名称下的/resources/templates/xxx.html，二是thymeleaf访问css及js路径默认在项目名称下的/resources/static/***因此编写时需要注意路径格式。

![image-20201018163327939](C:\Users\Rq.Gao\AppData\Roaming\Typora\typora-user-images\image-20201018163327939.png)

我们需要实现的功能逻辑是在浏览器模拟客户端访问http://localhost:8100/index，后台跳转出登陆表单，根据数据库中的信息，正确填写用户名和登陆信息后成功进入index页面。

### 2.2 后台控制

#### 2.2.1 ViewController

有两种实现viewController的方式，一种是新键配置类另一种是在controller层编写，本案例采取第二种方式进行编写。

```java
package cn.rqg.springboot_security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ViewControllers {
    @RequestMapping("/toLogin")
    public String toLoginPage(){
        return "MyLogin";
    }

    @GetMapping("/index")
    public String toIndexPage(){
        return "index";
    }
}
```

#### 2.2.2 实体类编写

数据库建表如下：

第一张表是用户信息表，包括id，username，password

```sql
CREATE TABLE `user_security` (
  `id` int(20) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) DEFAULT NULL,
  `password` varchar(50) DEFAULT NULL,
  `old_password` varchar(50) DEFAULT NULL,
  `new_password` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHA
```

第二张表是用户权限表，包括id，username，roles

```sql
CREATE TABLE `user_authorities` (
  `id` int(20) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) DEFAULT NULL,
  `roles` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `user_authorities_ibfk_1` FOREIGN KEY (`id`) REFERENCES `user_security` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8
```

编写对应的实体类分别是SysUser和SysAuthority

```java
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
```

```java
package cn.rqg.springboot_security.pojo;

import lombok.Data;
import java.io.Serializable;

@Data
public class SysAuthority implements Serializable {
    private int id;
    private String username;
    private String roles;//必须ROLE_开头,全大写
}
```

其中在权限实体类编写过程中需要注意要对权限名称以ROLE_开头，全大写。

#### 2.2.3 mapper和service层编写

由于只需要对用户进行查询操作，且仅限于登录功能，因此mapper和service层代码较为简单。

```java
package cn.rqg.springboot_security.mapper;

import cn.rqg.springboot_security.pojo.SysUser;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Mapper
@Repository
public interface SysUserMapper {
    SysUser findByUsername(String username);
}
```

```java
package cn.rqg.springboot_security.mapper;

import cn.rqg.springboot_security.pojo.SysAuthority;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Mapper
@Repository
public interface SysAuthoritiesMapper {
    SysAuthority getUserAuthorities(String username);
}
```

后序开发中为了方便前后端信息传递，可以将mapper返回类型更改为泛型。

```java
package cn.rqg.springboot_security.service;

import cn.rqg.springboot_security.pojo.SysAuthority;
import java.util.List;

public interface SysAuthoritiesService {
    List<SysAuthority> getUserAuthorities(String username);
}
```

```java
package cn.rqg.springboot_security.service;

import cn.rqg.springboot_security.pojo.SysUser;

public interface SysUserService {
    SysUser getUserByName(String username);
}
```

service实现类中需要包括自定义的UserDetailsService实现security自带的UserDetailsService接口，将在后序security核心编写时候说明。

```java
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
```

```java
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
```

#### 2.2.4 security核心编写

security核心是用户自定义的继承了WebSecurityConfigurerAdapter类的配置类。该配置类需要注入spring并开启security功能。具体代码实现如下：

```java
package cn.rqg.springboot_security.config;

import cn.rqg.springboot_security.service.impl.MyUserSecurityImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    MyUserSecurityImpl userSecurity;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/layui/**","/js/**","/toLogin","/login").permitAll()
                .anyRequest().authenticated();
        http
                .formLogin()
                .loginPage("/toLogin")
                .passwordParameter("password").usernameParameter("username")
                .loginProcessingUrl("/login");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userSecurity).passwordEncoder(passwordEncoder);
    }
}
```

首先定义资源访问权限，由于html页面用到了layui和js因此需要开启这些文件的静态资源访问权限，值得注意的是，由于需要访问我们的自定义登录页面和验证用户的login请求，因此需要开启这两者的请求权限。.formLogin()表示开启表单登陆，.loginPage("/xxx")自定义到登录页面（该映射已经在之前的controller曾编写）。.passwordParameter("password").usernameParameter("username")，是对表单中的input标签体中的name属性进行映射。.loginProcessingUrl("/login")表示自定义的验证请求，需要与表单发送请求一致。

随后重写验证方法，该方法中需要引入两个自定义的类包括userSecurity和passwordEncoder。根据security验证原理，userSecurity类实现了UserDetailsService接口，复写其中的loadDataSource方法。将数据库中获取到的username，password和authorities传递给security代码如下

```java
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
        String password = new BCryptPasswordEncoder().encode(sysUser.getPassword());
        User user = new User(sysUser.getUsername(),password,AuthorityUtils.commaSeparatedStringToAuthorityList(authorityList.toString()));
        return user;
    }
}
```

security新特性注重密码安全，因此在读取数据库中的password之后需要将其进行加密，随后传递给User类，这个User类是security自带的实现了UserDeatails接口的User类。

验证方法中引入的第二个类是自定义的密码加密类，该类实现了PasswordEncoding接口并复写了其中的方法。具体代码如下：

```java
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
```

值得注意的是，同一组密码先后经过BCryptPasswordEncoder加密后所得的加密结果不同，因此不可以简单判断，需要用BCryptPasswordEncoder自带的matches方法进行判断，第一个参数传入的是表单中提交的原生密码，第二个参数是数据库读取到的加密后的密码。

随后在浏览器中进入http://localhost:8100/index，首先进入到自定义的登录界面

![image-20201018172404748](C:\Users\Rq.Gao\AppData\Roaming\Typora\typora-user-images\image-20201018172404748.png)

输入数据库中的用户名和密码后成功进入到index界面。

