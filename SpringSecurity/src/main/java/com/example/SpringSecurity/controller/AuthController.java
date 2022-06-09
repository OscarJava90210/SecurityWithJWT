package com.example.SpringSecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/auth")
public class AuthController {

    @GetMapping
    public String getLoginPage(){
        return "login";
    }

    @GetMapping
    public String getSuccessPage(){
        return "success";
    }
}
