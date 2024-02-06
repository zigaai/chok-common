package com.zigaai.oauth2.config;

import com.zigaai.security.enumeration.LoginType;
import com.zigaai.security.filter.LoginAuthenticationFilter;
import com.zigaai.security.handler.DefaultAccessDeniedHandler;
import com.zigaai.security.handler.DefaultAuthenticationEntryPoint;
import com.zigaai.security.processor.LoginProcessor;
import com.zigaai.security.properties.CustomSecurityProperties;
import com.zigaai.security.provider.DaoMultiAuthenticationProvider;
import com.zigaai.security.service.MultiAuthenticationUserDetailsService;
import com.zigaai.security.service.TokenCacheService;
import com.zigaai.strategy.StrategyFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
// @Configuration
// @EnableWebSecurity
// @EnableConfigurationProperties(CustomSecurityProperties.class)
public class BaseResourceServerConfig {

    protected final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;

    // protected final JwtFilter jwtFilter;

    protected final CustomSecurityProperties securityProperties;

    protected final DefaultAccessDeniedHandler defaultAccessDeniedHandler;

    protected final DefaultAuthenticationEntryPoint defaultAuthenticationEntryPoint;

    protected final StrategyFactory<LoginType, LoginProcessor> loginTypeLoginProcessorStrategy;

    protected final StrategyFactory<String, MultiAuthenticationUserDetailsService> userDetailsServiceStrategy;

    protected final TokenCacheService tokenCacheService;

    // @Bean
    // @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // // DaoMultiAuthenticationProvider daoMultiAuthenticationProvider = new DaoMultiAuthenticationProvider();
        // // daoMultiAuthenticationProvider.setUserDetailsService(userDetailsService);
        // http
        //         .authorizeHttpRequests((authorize) -> authorize
        //                 .anyRequest().authenticated()
        //         )
        //         // Form login handles the redirect to the login page from the
        //         // authorization server filter chain
        //         // .formLogin(Customizer.withDefaults())
        //         .formLogin(AbstractHttpConfigurer::disable)
        //         .sessionManagement(AbstractHttpConfigurer::disable)
        //         .csrf(AbstractHttpConfigurer::disable)
        //         .logout(AbstractHttpConfigurer::disable)
        //         .exceptionHandling(config -> {
        //             config
        //                     .accessDeniedHandler((request, response, e) -> {
        //                         System.out.println("错误1: " + e.getLocalizedMessage());
        //                     })
        //                     .authenticationEntryPoint((request, response, e) -> {
        //                         System.out.println("错误2: " + e.getLocalizedMessage());
        //                     });
        //         })
        // // .authenticationManager(new ProviderManager(daoMultiAuthenticationProvider))
        // ;
        // http.addFilterBefore(new JwtFilter(systemUserRemoteService), AuthorizationFilter.class);
        //
        // return http.build();

        AuthenticationManager authenticationManager = buildAuthenticationManager();
        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(config -> config.requestMatchers(securityProperties.getIgnoreUrls().toArray(String[]::new))
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .exceptionHandling(config -> config
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                        .accessDeniedHandler(defaultAccessDeniedHandler))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                        .accessDeniedHandler(defaultAccessDeniedHandler)
                );

        // LoginAuthenticationFilter loginAuthenticationFilter = buildLoginFilter(authenticationManager);
        // http.addFilterAfter(loginAuthenticationFilter, HeaderWriterFilter.class)
        //         .addFilterBefore(jwtFilter, LoginAuthenticationFilter.class);

        return http.build();
    }

    protected LoginAuthenticationFilter buildLoginFilter(AuthenticationManager authenticationManager) {
        return new LoginAuthenticationFilter(loginTypeLoginProcessorStrategy,
                authenticationManager,
                securityProperties,
                jackson2HttpMessageConverter,
                tokenCacheService);
    }

    protected AuthenticationManager buildAuthenticationManager() {
        DaoMultiAuthenticationProvider daoMultiAuthenticationProvider = new DaoMultiAuthenticationProvider(userDetailsServiceStrategy, securityProperties);
        return new ProviderManager(daoMultiAuthenticationProvider);
    }

}
