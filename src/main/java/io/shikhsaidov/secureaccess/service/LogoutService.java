package io.shikhsaidov.secureaccess.service;

import io.shikhsaidov.secureaccess.repository.TokenRepository;
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
import static io.shikhsaidov.secureaccess.util.Utility.object2Json;

@Log4j2
@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
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

        log.info("Successfully logged out!");
        String logoutJsonResponse = object2Json(
                response(
                        SUCCESS,
                        "successfully logged out",
                        null
                )
        );
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.OK.value());
        try {
            response.getWriter().write(logoutJsonResponse);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}
