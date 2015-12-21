package com.oz.gateway.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Created by Ozgur V. Amac on 12/5/15.
 */
@RestController
@RequestMapping(value = "/sunapee-mock")
public class UserController {

    @RequestMapping("/user-api")
    public Principal user(Principal user) {
        return user;
    }
}
