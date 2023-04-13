package io.shikhsaidov.secureaccess.service;

import io.shikhsaidov.secureaccess.repository.TokenRepository;
import io.shikhsaidov.secureaccess.util.LogDetail;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.io.IOException;

import static io.shikhsaidov.secureaccess.response.Response.response;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.SUCCESS;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.TOKEN_IS_INVALID_OR_EXPIRED;
import static io.shikhsaidov.secureaccess.util.Utility.isNull;
import static io.shikhsaidov.secureaccess.util.Utility.object2Json;

@Log4j2
@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;
    private final LogDetail logDetail;

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader("Authorization");
        log.info(
                "requestPath: '{}', clientIp: '{}', " +
                        "function calling with request parameters: token='{}'",
                logDetail.getRequestPath(),
                logDetail.getIp(),
                authHeader
        );
        final String jwt;
        if (isNull(authHeader) || !authHeader.startsWith("Bearer ")) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: " +
                            "token is not valid or expired",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );

            String invalidTokenJsonResponse = object2Json(response(TOKEN_IS_INVALID_OR_EXPIRED));
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            try {
                response.getWriter().write(invalidTokenJsonResponse);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return;
        }
        jwt = authHeader.substring(7);
        var storedToken = tokenRepository.findByToken(jwt)
                .orElse(null);
        if (storedToken != null) {
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
            SecurityContextHolder.clearContext();
        }

        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        String logoutJsonResponse = object2Json(response(SUCCESS));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.OK.value());
        try {
            response.getWriter().write(logoutJsonResponse);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}
