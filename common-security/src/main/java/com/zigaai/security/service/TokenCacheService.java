package com.zigaai.security.service;

import com.zigaai.constants.SecurityConstant;
import com.zigaai.exception.RefreshTokenExpiredException;
import com.zigaai.model.security.PayloadDTO;
import com.zigaai.model.security.UPMSToken;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Getter
@RequiredArgsConstructor
public class TokenCacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    @SuppressWarnings("unchecked")
    public void cacheRefreshToken(UPMSToken upmsToken, PayloadDTO payload) {
        long refreshTimeToLive = upmsToken.getRefreshExpiresIn();
        String refreshToken = upmsToken.getRefreshToken();
        String refreshTokenInfoKey = SecurityConstant.CacheKey.REFRESH_TOKEN_INFO(refreshToken);
        String userRefreshTokensKey = SecurityConstant.CacheKey.USER_REFRESH_TOKEN(payload.getUserType(), payload.getUsername());
        HashSet<String> refreshTokens = (HashSet<String>) redisTemplate.opsForValue().get(userRefreshTokensKey);
        if (CollectionUtils.isEmpty(refreshTokens)) {
            refreshTokens = new HashSet<>();
        }
        refreshTokens.add(refreshToken);
        Map<String, Serializable> map = Map.of(refreshTokenInfoKey, payload,
                userRefreshTokensKey, refreshTokens);
        redisTemplate.opsForValue().multiSet(map);
        redisTemplate.expire(userRefreshTokensKey, refreshTimeToLive, TimeUnit.SECONDS);
        redisTemplate.expire(refreshTokenInfoKey, refreshTimeToLive, TimeUnit.SECONDS);
    }

    @SuppressWarnings("unchecked")
    public void clearRefreshToken(String userType, String username) {
        HashSet<String> existRefreshTokens = (HashSet<String>) redisTemplate.opsForValue().get(SecurityConstant.CacheKey.USER_REFRESH_TOKEN(userType, username));
        List<String> keys = new ArrayList<>();
        if (!CollectionUtils.isEmpty(existRefreshTokens)) {
            for (String item : existRefreshTokens) {
                keys.add(SecurityConstant.CacheKey.REFRESH_TOKEN_INFO(item));
            }
        }
        keys.add(SecurityConstant.CacheKey.USER_REFRESH_TOKEN(userType, username));
        redisTemplate.delete(keys);
    }

    public PayloadDTO getRefreshTokenInfo(String refreshToken) {
        String refreshTokenKey = SecurityConstant.CacheKey.REFRESH_TOKEN_INFO(refreshToken);
        PayloadDTO payload = (PayloadDTO) redisTemplate.opsForValue().get(refreshTokenKey);
        if (payload == null) {
            throw new RefreshTokenExpiredException("refresh token 已过期, 请重新登录");
        }
        return payload;
    }

    @SuppressWarnings("unchecked")
    public HashSet<String> getRefreshTokens(String userType, String username) {
        String userRefreshTokenKey = SecurityConstant.CacheKey.USER_REFRESH_TOKEN(userType, username);
        return (HashSet<String>) redisTemplate.opsForValue().get(userRefreshTokenKey);
    }

}
