package io.shikhsaidov.secureaccess.service.impl;

import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.response.model.EnvResponse;
import io.shikhsaidov.secureaccess.service.AdminService;
import io.shikhsaidov.secureaccess.util.LogDetail;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import static io.shikhsaidov.secureaccess.response.Response.*;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.*;
import static java.util.Objects.isNull;

@Log4j2
@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

    private final LogDetail logDetail;

    @Value("${application.environment}")
    public String environment;

    @Override
    public Response<?> getEnvironment() {

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
}
