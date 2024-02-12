package com.zigaai.oauth2.config;

import com.zigaai.oauth2.handler.OAuth2AuthenticationEntryPoint;
import com.zigaai.oauth2.handler.OAuth2AuthenticationSuccessHandler;
import com.zigaai.oauth2.handler.OAuth2AuthorizationErrorHandler;
import com.zigaai.oauth2.keygen.UUIDOAuth2AuthorizationCodeGenerator;
import com.zigaai.oauth2.service.RedisOAuth2AuthorizationConsentService;
import com.zigaai.oauth2.service.RedisOAuth2AuthorizationService;
import com.zigaai.security.filter.JwtFilter;
import com.zigaai.security.handler.DefaultAccessDeniedHandler;
import com.zigaai.security.handler.DefaultAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.CollectionUtils;

import java.util.Arrays;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
// @Configuration
// @EnableWebSecurity
public class BaseAuthorizationServerConfig {

    protected final OAuth2AuthenticationEntryPoint oauth2AuthenticationEntryPoint;

    protected final RegisteredClientRepository registeredClientRepository;

    protected final RedisOAuth2AuthorizationService redisOAuth2AuthorizationService;

    protected final OAuth2AuthorizationErrorHandler oauth2AuthorizationErrorHandler;

    protected final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    protected final DefaultAccessDeniedHandler defaultAccessDeniedHandler;

    protected final DefaultAuthenticationEntryPoint defaultAuthenticationEntryPoint;

    protected final JwtFilter jwtFilter;

    protected final RedisOAuth2AuthorizationConsentService redisOAuth2AuthorizationConsentService;

    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults())    // Enable OpenID Connect 1.0
                .clientAuthentication(clientAuthentication -> clientAuthentication.errorResponseHandler(oauth2AuthorizationErrorHandler))
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.errorResponseHandler(oauth2AuthorizationErrorHandler)
                                .authenticationProviders(authenticationProviders -> {
                                    if (!CollectionUtils.isEmpty(authenticationProviders)) {
                                        authenticationProviders.subList(0, authenticationProviders.size()).clear();
                                    }
                                    authenticationProviders.addAll(buildProviders());
                                })
                        // .consentPage("https://cn.bing.com")
                )
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .errorResponseHandler(oauth2AuthorizationErrorHandler)
                        .accessTokenResponseHandler(oAuth2AuthenticationSuccessHandler)
                        // .accessTokenRequestConverters(converters -> converters.add(0, buildOAuth2AutoRefreshTokenAuthenticationConverter()))
                );
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                        .authenticationEntryPoint(oauth2AuthenticationEntryPoint)
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .accessDeniedHandler(defaultAccessDeniedHandler)
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .anonymous(AbstractHttpConfigurer::disable);
        http.addFilterAfter(jwtFilter, SecurityContextHolderFilter.class);
        return http.build();
    }

    protected List<AuthenticationProvider> buildProviders() {
        UUIDOAuth2AuthorizationCodeGenerator uuidoAuth2AuthorizationCodeGenerator = new UUIDOAuth2AuthorizationCodeGenerator();
        OAuth2AuthorizationCodeRequestAuthenticationProvider oAuth2AuthorizationCodeRequestAuthenticationProvider =
                new OAuth2AuthorizationCodeRequestAuthenticationProvider(
                        registeredClientRepository,
                        redisOAuth2AuthorizationService,
                        redisOAuth2AuthorizationConsentService
                );
        oAuth2AuthorizationCodeRequestAuthenticationProvider.setAuthorizationCodeGenerator(uuidoAuth2AuthorizationCodeGenerator);
        OAuth2AuthorizationConsentAuthenticationProvider oAuth2AuthorizationConsentAuthenticationProvider =
                new OAuth2AuthorizationConsentAuthenticationProvider(
                        registeredClientRepository,
                        redisOAuth2AuthorizationService,
                        redisOAuth2AuthorizationConsentService
                );
        oAuth2AuthorizationConsentAuthenticationProvider.setAuthorizationCodeGenerator(uuidoAuth2AuthorizationCodeGenerator);
        return Arrays.asList(oAuth2AuthorizationCodeRequestAuthenticationProvider, oAuth2AuthorizationConsentAuthenticationProvider);
    }

}
