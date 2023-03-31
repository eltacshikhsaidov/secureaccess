package io.shikhsaidov.secureaccess.service.impl;

import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.response.model.EnvResponse;
import io.shikhsaidov.secureaccess.service.AdminService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import static io.shikhsaidov.secureaccess.response.Response.*;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.*;
import static java.util.Objects.isNull;

@Log4j2
@Service
public class AdminServiceImpl implements AdminService {

    @Value("${application.environment}")
    public String environment;

    @Override
    public Response<?> getEnvironment() {

        if (isNull(environment)) {
            log.warn("No environment is present");
            return failed(
                    NO_ENVIRONMENT_IS_PRESENT,
                    "No environment is present"
            );
        }

        return success(
                "success",
                EnvResponse.builder()
                        .environment(environment)
                        .build()
        );
    }
}
