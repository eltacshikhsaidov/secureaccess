package io.shikhsaidov.secureaccess.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/test")
public class DemoController {


    @GetMapping(path = "/t")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> sayHello() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(a.getAuthorities());
        return ResponseEntity.ok("Hello from secured endpoint");
    }

    @GetMapping(path = "/public")
    public String publicEndpoint() {
        return "public endpoint";
    }

}
