package io.shikhsaidov.secureaccess.config;

import io.shikhsaidov.secureaccess.holder.HeaderHolder;
import io.shikhsaidov.secureaccess.interceptor.HeaderInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class HeaderInterceptorConfig implements WebMvcConfigurer {

    @Bean
    @Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public HeaderHolder headerHolder() {
        return new HeaderHolder();
    }
    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(headerInterceptor());
    }

    @Bean
    public HeaderInterceptor headerInterceptor() {
        return new HeaderInterceptor(headerHolder());
    }
}
