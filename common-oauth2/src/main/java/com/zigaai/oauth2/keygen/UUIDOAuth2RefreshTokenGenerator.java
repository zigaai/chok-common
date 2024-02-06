package com.zigaai.oauth2.keygen;

import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;

/**
 * 刷新Token生成器
 */
public class UUIDOAuth2RefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private static final UUIDStringKeyGenerator UUID_STRING_KEY_GENERATOR = new UUIDStringKeyGenerator();

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(UUID_STRING_KEY_GENERATOR.generateKey(), issuedAt, expiresAt);
    }
}
