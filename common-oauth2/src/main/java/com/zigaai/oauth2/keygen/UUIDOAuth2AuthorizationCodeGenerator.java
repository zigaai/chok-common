package com.zigaai.oauth2.keygen;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;

/**
 * 自定义OAuth2授权码生成器
 */
public class UUIDOAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {

    private static final UUIDStringKeyGenerator UUID_STRING_KEY_GENERATOR = new UUIDStringKeyGenerator();

    @Override
    public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
        if (context.getTokenType() == null ||
                !OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
            return null;
        }
        RegisteredClient registeredClient = context.getRegisteredClient();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive());
        return new OAuth2AuthorizationCode(UUID_STRING_KEY_GENERATOR.generateKey(), issuedAt, expiresAt);
    }
}
