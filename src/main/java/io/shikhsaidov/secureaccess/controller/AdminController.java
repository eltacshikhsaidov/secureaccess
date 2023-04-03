package io.shikhsaidov.secureaccess.controller;

import io.shikhsaidov.secureaccess.enums.Status;
import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/v1/admin")
@PreAuthorize("hasAuthority('ADMIN')")
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;
    @GetMapping(path = "/application/environment")
    public Response<?> getEnvironment() {
        return adminService.getEnvironment();
    }

    @GetMapping(path = "/users")
    public Response<?> getUsers(
            @RequestParam(name = "status", defaultValue = "ACTIVE") Status status,
            @RequestParam(name = "locked", defaultValue = "false") boolean isLocked,
            @RequestParam(name = "enabled", defaultValue = "true") boolean isEnabled
            ) {
        return adminService.getUsers(status, isLocked, isEnabled);
    }

}
