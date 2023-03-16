package io.shikhsaidov.secureaccess.controller;

import io.shikhsaidov.secureaccess.dto.LoginDTO;
import io.shikhsaidov.secureaccess.dto.RegisterDTO;
import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public Response<?> register(@RequestBody RegisterDTO request) {
        return service.register(request);
    }
    @PostMapping("/login")
    public Response<?> login(@RequestBody LoginDTO request) {
        return service.login(request);
    }

}
