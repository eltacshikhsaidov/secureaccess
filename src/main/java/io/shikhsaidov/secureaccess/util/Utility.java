package io.shikhsaidov.secureaccess.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Random;

@Log4j2
public class Utility {
    public static boolean isNull(Object... objects) {
        for (Object o : objects) {
            if (java.util.Objects.isNull(o)) {
                return true;
            }
        }

        return false;
    }

    public static String object2Json(Object o) {
        String jsonString = null;

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            jsonString = objectMapper.writeValueAsString(o);

        } catch (JsonProcessingException e) {
            log.warn("Failed while converting object to json string");
        }

        return jsonString;
    }

    public static HttpServletRequest getCurrentRequest() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            if (requestAttributes instanceof ServletRequestAttributes) {
                return ((ServletRequestAttributes) requestAttributes).getRequest();
            }
        }
        return null;
    }

    public static String getClientIp(HttpServletRequest request) {
        if (request != null) {
            String remoteAddr = request.getHeader("X-Forwarded-For");
            if (remoteAddr == null)
                remoteAddr = request.getRemoteAddr();
            return remoteAddr;
        } else {
            return null;
        }
    }

    public static String getRequestPath(HttpServletRequest httpServletRequest) {
        if (httpServletRequest != null) {
            String requestUri = httpServletRequest.getRequestURI();
            return requestUri.substring(httpServletRequest.getContextPath().length());
        } else {
            return null;
        }

    }
    public static int randomBetween(int min, int max) {
        Random rand = new Random();
        return rand.nextInt((max - min) + 1) + min;
    }

}
