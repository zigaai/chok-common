package com.zigaai.oauth2.config;

import com.zigaai.security.handler.DefaultAccessDeniedHandler;
import com.zigaai.security.handler.DefaultAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
public class BaseSecurityConfig {

    protected final DefaultAccessDeniedHandler defaultAccessDeniedHandler;

    protected final DefaultAuthenticationEntryPoint defaultAuthenticationEntryPoint;

    public SecurityFilterChain defaultResourceSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .sessionManagement(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                        .accessDeniedHandler(defaultAccessDeniedHandler)
                )
                .exceptionHandling(config -> config
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                        .accessDeniedHandler(defaultAccessDeniedHandler)
                )
        ;
        return http.build();
    }
}
