package io.shikhsaidov.secureaccess.service.impl;

import io.shikhsaidov.secureaccess.entity.User;
import io.shikhsaidov.secureaccess.enums.Status;
import io.shikhsaidov.secureaccess.repository.UserRepository;
import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.response.model.EnvResponse;
import io.shikhsaidov.secureaccess.response.model.UsersResponse;
import io.shikhsaidov.secureaccess.service.AdminService;
import io.shikhsaidov.secureaccess.util.LogDetail;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

import static io.shikhsaidov.secureaccess.response.Response.*;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.*;
import static java.util.Objects.isNull;

@Log4j2
@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

    private final LogDetail logDetail;
    private final UserRepository userRepository;

    @Value("${application.environment}")
    public String environment;

    @Override
    public Response<?> getEnvironment() {
        log.info(
                "requestPath: '{}', clientIp: '{}', calling function without parameters",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );

        if (isNull(environment)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: environment is not specified",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    NO_ENVIRONMENT_IS_PRESENT,
                    "No environment is present"
            );
        }

        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return success(
                "success",
                EnvResponse.builder()
                        .environment(environment)
                        .build()
        );
    }

    @Override
    public Response<?> getUsers(Status status, boolean locked, boolean enabled) {
        log.info(
                "requestPath: '{}', clientIp: '{}', calling function with parameters: " +
                        "status='{}', " +
                        "locked='{}', " +
                        "enabled='{}'",
                logDetail.getRequestPath(),
                logDetail.getIp(),
                status.name(),
                locked,
                enabled
        );

        List<User> users = userRepository.findUsersByStatusAndLockedAndEnabled(status, locked, enabled);

        users.forEach(
                user -> user.setPassword("**********")
        );

        log.info(
                "requestPath: '{}', clientIp: '{}', calling function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return success("success", UsersResponse.builder().users(users).build());
    }
}
