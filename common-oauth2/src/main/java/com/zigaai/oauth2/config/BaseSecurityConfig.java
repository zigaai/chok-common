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

    // @Bean
    // @Order(3)
    // @ConditionalOnBean(AuthenticationRemoteService.class)
    public SecurityFilterChain defaultResourceSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                // .formLogin(Customizer.withDefaults());
                .sessionManagement(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(resourceServer -> resourceServer
                        // TODO 用户信息表存 Authorization Server 中, 每次通过feign调用并缓存Redis
                        // .jwt(new Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer>() {
                        //     @Override
                        //     public void customize(OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwtConfigurer) {
                        //         jwtConfigurer.jwtAuthenticationConverter(new Converter<Jwt, AbstractAuthenticationToken>() {
                        //             @Override
                        //             public AbstractAuthenticationToken convert(Jwt source) {
                        //                 log.info("claims: {}", source.getClaims());
                        //                 return new UsernamePasswordAuthenticationToken();
                        //             }
                        //         });
                        //     }
                        // })
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
