package io.shikhsaidov.secureaccess.handler;

import io.shikhsaidov.secureaccess.exception.TokenNotFound;
import io.shikhsaidov.secureaccess.response.Response;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static io.shikhsaidov.secureaccess.response.Response.failed;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.CONFIRMATION_TOKEN_NOT_FOUND;

@Log4j2
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler({TokenNotFound.class})
    public Response<?> handleTokenNotFoundException(TokenNotFound e) {
        log.warn("confirmation token not found, exception message: {}", e.getMessage());
        return failed(CONFIRMATION_TOKEN_NOT_FOUND, "confirmation token not found");
    }
}
