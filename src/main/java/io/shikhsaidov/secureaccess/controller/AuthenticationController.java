package io.shikhsaidov.secureaccess.controller;

import io.shikhsaidov.secureaccess.dto.LoginDTO;
import io.shikhsaidov.secureaccess.dto.RegisterDTO;
import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping(path = "/register")
    public Response<?> register(@RequestBody RegisterDTO request) {
        return service.register(request);
    }
    @PostMapping(path = "/login")
    public Response<?> login(@RequestBody LoginDTO request) {
        return service.login(request);
    }

    @GetMapping(path = "/confirm")
    public Response<?> confirmToken(@RequestParam(name = "token") String token) {
        return service.confirmToken(token);
    }

}
