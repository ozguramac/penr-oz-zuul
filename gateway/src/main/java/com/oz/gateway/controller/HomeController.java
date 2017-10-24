package com.oz.gateway.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by Ozgur V. Amac on 1/17/16.
 */
@RestController
public class HomeController {

    @RequestMapping("/")
    String home() {
        return "Welcome Home!";
    }

}
