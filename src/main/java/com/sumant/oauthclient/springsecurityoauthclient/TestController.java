package com.sumant.oauthclient.springsecurityoauthclient;

import org.springframework.context.annotation.Role;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/test")
    public String sayHelloTest(){
        return "Hello Test";
    }

}
