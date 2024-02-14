package com.zigaai.security.config;

import com.zigaai.security.handler.DefaultAccessDeniedHandler;
import com.zigaai.security.handler.DefaultAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
public abstract class BaseResourceServerConfig {

    protected final DefaultAccessDeniedHandler defaultAccessDeniedHandler;

    protected final DefaultAuthenticationEntryPoint defaultAuthenticationEntryPoint;

    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        String[] ignoreUrls = ignoreUrls();
        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(config -> {
                            if (ignoreUrls != null && ignoreUrls.length > 0) {
                                config.requestMatchers(ignoreUrls)
                                        .permitAll();
                            }
                            config.anyRequest()
                                    .authenticated();
                        }
                )
                .exceptionHandling(config -> config
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                        .accessDeniedHandler(defaultAccessDeniedHandler))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                        .accessDeniedHandler(defaultAccessDeniedHandler)
                );
        postProcessAfterInitialization(http);
        return http.build();
    }

    protected void postProcessAfterInitialization(HttpSecurity http) {}

    protected String[] ignoreUrls() {
        return new String[0];
    }

}
