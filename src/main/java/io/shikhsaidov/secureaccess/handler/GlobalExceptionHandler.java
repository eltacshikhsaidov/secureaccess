package io.shikhsaidov.secureaccess.handler;

import io.jsonwebtoken.ExpiredJwtException;
import io.shikhsaidov.secureaccess.exception.TokenNotFound;
import io.shikhsaidov.secureaccess.response.Response;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static io.shikhsaidov.secureaccess.response.Response.failed;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.CONFIRMATION_TOKEN_NOT_FOUND;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.TOKEN_IS_INVALID_OR_EXPIRED;

@Log4j2
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler({ExpiredJwtException.class})
    public Response<?> handleInvalidTokenException(ExpiredJwtException e) {
        log.warn("Token is either expired or invalid");
        return failed(TOKEN_IS_INVALID_OR_EXPIRED, "token is either expired or invalid");
    }

    @ExceptionHandler({TokenNotFound.class})
    public Response<?> handleTokenNotFoundException(TokenNotFound e) {
        log.warn("confirmation token not found");
        return failed(CONFIRMATION_TOKEN_NOT_FOUND, "confirmation token not found");
    }
}
