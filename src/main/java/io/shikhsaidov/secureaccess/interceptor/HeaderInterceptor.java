package io.shikhsaidov.secureaccess.interceptor;

import io.shikhsaidov.secureaccess.holder.HeaderHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.HandlerInterceptor;

import static io.shikhsaidov.secureaccess.util.Utility.isNull;

@RequiredArgsConstructor
public class HeaderInterceptor implements HandlerInterceptor {
    private final HeaderHolder headerHolder;

    @Override
    public boolean preHandle(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Object handler
    ) {
        String userAgent = request.getHeader("User-Agent");
        headerHolder.setUserAgent(isNull(userAgent) ? "Unrecognized" : userAgent);
        return true;
    }

}
