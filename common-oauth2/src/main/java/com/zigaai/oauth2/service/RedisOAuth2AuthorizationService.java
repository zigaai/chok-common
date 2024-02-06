package com.zigaai.oauth2.service;

import com.zigaai.oauth2.constants.OAuth2RedisKeys;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

// @Service
@RequiredArgsConstructor
public final class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final RegisteredClientRepository registeredClientRepository;

    private final RedisTemplate<String, Object> redisTemplate;

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        RegisteredClient registeredClient = registeredClientRepository.findById(authorization.getRegisteredClientId());
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), "client id:" + authorization.getRegisteredClientId() + " is not exist");
        }

        long refreshTokenTimeToLive = registeredClient.getTokenSettings().getRefreshTokenTimeToLive().toSeconds();
        long accessTokenTimeToLive = registeredClient.getTokenSettings().getAccessTokenTimeToLive().toSeconds();

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            long authorizationCodeTimeToLive = registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive().toSeconds();
            if (authorizationCode.getToken() == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), "authorization code can not be null");
            }
            redisTemplate.opsForValue().set(OAuth2RedisKeys.AUTHORIZATION_CODE(authorizationCode.getToken().getTokenValue()), authorization.getId(), authorizationCodeTimeToLive, TimeUnit.SECONDS);
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        if (accessToken != null) {
            if (accessToken.getToken() == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), "access token can not be null");
            }
            redisTemplate.opsForValue().set(OAuth2RedisKeys.ACCESS_TOKEN(accessToken.getToken().getTokenValue()), authorization.getId(), accessTokenTimeToLive, TimeUnit.SECONDS);
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken != null) {
            if (refreshToken.getToken() == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), "refresh token can not be null");
            }
            if (refreshToken.getToken().getExpiresAt() == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), "refresh token expires_at can not be null");
            }
            redisTemplate.opsForValue().set(OAuth2RedisKeys.REFRESH_TOKEN(refreshToken.getToken().getTokenValue()), authorization.getId(), refreshTokenTimeToLive, TimeUnit.SECONDS);
        }

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            if (oidcIdToken.getToken() == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), "oidc token can not be null");
            }
            if (oidcIdToken.getToken().getExpiresAt() == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), "oidc token expires_at can not be null");
            }
            redisTemplate.opsForValue().set(OAuth2RedisKeys.OIDC_TOKEN(oidcIdToken.getToken().getTokenValue()), authorization.getId(), accessTokenTimeToLive, TimeUnit.SECONDS);
        }

        String authorizationState = authorization.getAttribute(OAuth2ParameterNames.STATE);
        if (StringUtils.hasText(authorizationState)) {
            redisTemplate.opsForValue().set(OAuth2RedisKeys.OAUTH2_STATE_CODE(authorizationState), authorization.getId(), refreshTokenTimeToLive, TimeUnit.SECONDS);
        }
        redisTemplate.opsForValue().set(OAuth2RedisKeys.RESOURCE_PRINCIPAL(authorization.getPrincipalName(), authorization.getId()), authorization.getRegisteredClientId(), refreshTokenTimeToLive, TimeUnit.SECONDS);
        redisTemplate.opsForValue().set(OAuth2RedisKeys.OAUTH2_AUTHORIZATION(authorization.getId()), authorization, refreshTokenTimeToLive, TimeUnit.SECONDS);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        List<String> delKeys = new ArrayList<>();
        delKeys.add(OAuth2RedisKeys.OAUTH2_AUTHORIZATION(authorization.getId()));

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null && authorizationCode.getToken() != null) {
            String authorizationCodeKey = OAuth2RedisKeys.AUTHORIZATION_CODE(authorizationCode.getToken().getTokenValue());
            delKeys.add(authorizationCodeKey);
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        if (accessToken != null && accessToken.getToken() != null) {
            String accessTokenKey = OAuth2RedisKeys.ACCESS_TOKEN(accessToken.getToken().getTokenValue());
            delKeys.add(accessTokenKey);
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken != null && refreshToken.getToken() != null) {
            String refreshTokenKey = OAuth2RedisKeys.REFRESH_TOKEN(refreshToken.getToken().getTokenValue());
            delKeys.add(refreshTokenKey);
        }

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null && oidcIdToken.getToken() != null) {
            String oidcTokenKey = OAuth2RedisKeys.OIDC_TOKEN(oidcIdToken.getToken().getTokenValue());
            delKeys.add(oidcTokenKey);
        }

        redisTemplate.delete(delKeys);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return (OAuth2Authorization) redisTemplate.opsForValue().get(OAuth2RedisKeys.OAUTH2_AUTHORIZATION(id));
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return null;
        }
        String key = null;
        if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            key = (String) redisTemplate.opsForValue().get(OAuth2RedisKeys.OAUTH2_STATE_CODE(token));
        }
        if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            key = (String) redisTemplate.opsForValue().get(OAuth2RedisKeys.AUTHORIZATION_CODE(token));
        }
        if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            key = (String) redisTemplate.opsForValue().get(OAuth2RedisKeys.ACCESS_TOKEN(token));
        }
        if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            key = (String) redisTemplate.opsForValue().get(OAuth2RedisKeys.REFRESH_TOKEN(token));
        }
        if (key == null) {
            return null;
        }
        return (OAuth2Authorization) redisTemplate.opsForValue().get(OAuth2RedisKeys.OAUTH2_AUTHORIZATION(key));
    }
}
