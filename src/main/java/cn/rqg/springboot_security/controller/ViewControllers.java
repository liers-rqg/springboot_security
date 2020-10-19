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
