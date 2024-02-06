package com.zigaai.oauth2.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.util.Assert;

import java.util.Objects;

// @Service
@RequiredArgsConstructor
public final class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        int id = getId(authorizationConsent);
        redisTemplate.opsForValue().set(String.valueOf(id), authorizationConsent);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        int id = getId(authorizationConsent);
        redisTemplate.delete(String.valueOf(id));
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        int id = getId(registeredClientId, principalName);
        return (OAuth2AuthorizationConsent) redisTemplate.opsForValue().get(String.valueOf(id));
    }

    private static int getId(OAuth2AuthorizationConsent authorizationConsent) {
        return getId(authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
    }

    private static int getId(String registeredClientId, String principalName) {
        return Objects.hash(registeredClientId, principalName);
    }

}
