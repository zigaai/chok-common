package com.zigaai.oauth2.repo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.zigaai.model.security.Oauth2RegisteredClientModel;
import com.zigaai.oauth2.constants.OAuth2RedisKeys;
import com.zigaai.utils.JsonUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class DaoRegisteredClientRepository implements RegisteredClientRepository {

    private final RedisTemplate<String, Object> redisTemplate;

    private final Oauth2RegisteredClientMapper oauth2RegisteredClientMapper;

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException();
    }

    @Override
    public RegisteredClient findById(String clientId) {
        return findByClientId(clientId);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        String key = OAuth2RedisKeys.OAUTH2_REGISTERED_CLIENT(clientId);
        RegisteredClient client = (RegisteredClient) redisTemplate.opsForValue().get(key);
        if (client != null) {
            return client;
        }
        Oauth2RegisteredClientModel registeredClient = oauth2RegisteredClientMapper.getByClientId(clientId);
        if (registeredClient == null) {
            return null;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(registeredClient.getClientId())
                .clientId(registeredClient.getClientId())
                .clientIdIssuedAt(registeredClient.getClientIdIssuedAt().toInstant())
                .clientName(registeredClient.getClientName())
                .clientSecret(registeredClient.getClientSecret())
                .clientName(registeredClient.getClientName())
                .clientAuthenticationMethods(clientAuthenticationMethods ->
                        clientAuthenticationMethods.addAll(
                                StringUtils.commaDelimitedListToSet(registeredClient.getClientAuthenticationMethods()).stream().map(ClientAuthenticationMethod::new).toList()
                        )
                )
                .authorizationGrantTypes(authorizationGrantTypes -> authorizationGrantTypes.addAll(
                        StringUtils.commaDelimitedListToSet(registeredClient.getAuthorizationGrantTypes()).stream().map(AuthorizationGrantType::new).toList()
                ))
                .redirectUris(redirectUris -> redirectUris.addAll(StringUtils.commaDelimitedListToSet(registeredClient.getRedirectUris())))
                .scopes(scopes -> scopes.addAll(StringUtils.commaDelimitedListToSet(registeredClient.getScopes())));
        if (registeredClient.getClientSecretExpiresAt() != null) {
            builder.clientSecretExpiresAt(registeredClient.getClientSecretExpiresAt().toInstant());
        }
        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
                .requireProofKey(false)
                .requireAuthorizationConsent(true);
        Map<String, Object> clientSettingsMap = this.parseClientSettings(registeredClient);
        if (!CollectionUtils.isEmpty(clientSettingsMap)) {
            clientSettingsMap.forEach((k, v) -> {
                if (v != null) {
                    clientSettingsBuilder.setting(k, v);
                }
            });
        }
        clientSettingsBuilder.requireAuthorizationConsent(false);
        builder.clientSettings(clientSettingsBuilder.build());
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder()
                .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                .accessTokenTimeToLive(Duration.ofMinutes(60))
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .deviceCodeTimeToLive(Duration.ofMinutes(5))
                .reuseRefreshTokens(false)
                .refreshTokenTimeToLive(Duration.ofDays(7))
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256);
        Map<String, Object> tokenSettingsMap = this.parseTokenSettings(registeredClient);
        if (!CollectionUtils.isEmpty(tokenSettingsMap)) {
            tokenSettingsMap.forEach((k, v) -> {
                if (v != null) {
                    tokenSettingsBuilder.setting(k, v);
                }
            });
        }
        tokenSettingsBuilder.reuseRefreshTokens(false);
        builder.tokenSettings(tokenSettingsBuilder.build());
        if (StringUtils.hasText(registeredClient.getPostLogoutRedirectUris())) {
            builder.postLogoutRedirectUris(logoutRedirectUris -> logoutRedirectUris.addAll(StringUtils.commaDelimitedListToSet(registeredClient.getPostLogoutRedirectUris())));
        }
        client = builder.build();
        redisTemplate.opsForValue().set(key, client);
        return client;
    }

    @SuppressWarnings("unchecked")
    protected Map<String, Object> parseClientSettings(Oauth2RegisteredClientModel registeredClient) {
        Map<String, Object> map = Collections.emptyMap();
        String clientSettings = registeredClient.getClientSettings();
        if (StringUtils.hasText(clientSettings)) {
            try {
                map = JsonUtil.readValue(clientSettings, Map.class);
            } catch (JsonProcessingException e) {
                log.error("解析客户端clientSettings字段错误, 将使用默认配置; err: {}", ExceptionUtils.getStackTrace(e));
            }
            Object requireProofKeyObj = map.get(ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY);
            if (requireProofKeyObj != null) {
                map.put(ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY, Boolean.parseBoolean(requireProofKeyObj.toString()));
            }
            Object requireAuthorizationConsentObj = map.get(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT);
            if (requireAuthorizationConsentObj != null) {
                map.put(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT, Boolean.parseBoolean(requireAuthorizationConsentObj.toString()));
            }
            Object jwkSetUrlObj = map.get(ConfigurationSettingNames.Client.JWK_SET_URL);
            if (jwkSetUrlObj != null) {
                map.put(ConfigurationSettingNames.Client.JWK_SET_URL, jwkSetUrlObj.toString());
            }
            Object tokenEndpointAuthenticationSigningAlgorithmObj = map.get(ConfigurationSettingNames.Client.TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM);
            if (tokenEndpointAuthenticationSigningAlgorithmObj != null) {
                map.put(ConfigurationSettingNames.Client.TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM, SignatureAlgorithm.from(tokenEndpointAuthenticationSigningAlgorithmObj.toString()));
            }
            Object accessTokenFormatObj = map.get(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT);
            if (accessTokenFormatObj != null) {
                map.put(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT, new OAuth2TokenFormat(accessTokenFormatObj.toString()));
            }
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    protected Map<String, Object> parseTokenSettings(Oauth2RegisteredClientModel registeredClient) {
        Map<String, Object> map = Collections.emptyMap();
        String tokenSettings = registeredClient.getTokenSettings();
        if (StringUtils.hasText(tokenSettings)) {
            try {
                map = JsonUtil.readValue(tokenSettings, Map.class);
            } catch (JsonProcessingException e) {
                log.error("解析客户端tokenSettings字段错误, 将使用默认配置; err: {}", ExceptionUtils.getStackTrace(e));
            }
            Object authorizationCodeTimeToLiveObj = map.get(ConfigurationSettingNames.Token.AUTHORIZATION_CODE_TIME_TO_LIVE);
            if (authorizationCodeTimeToLiveObj != null) {
                map.put(ConfigurationSettingNames.Token.AUTHORIZATION_CODE_TIME_TO_LIVE, Duration.ofSeconds(Long.parseLong(authorizationCodeTimeToLiveObj.toString())));
            }
            Object accessTokenTimeToLiveObj = map.get(ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE);
            if (accessTokenTimeToLiveObj != null) {
                map.put(ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE, Duration.ofSeconds(Long.parseLong(accessTokenTimeToLiveObj.toString())));
            }
            Object deviceCodeTimeToLiveObj = map.get(ConfigurationSettingNames.Token.DEVICE_CODE_TIME_TO_LIVE);
            if (deviceCodeTimeToLiveObj != null) {
                map.put(ConfigurationSettingNames.Token.DEVICE_CODE_TIME_TO_LIVE, Duration.ofSeconds(Long.parseLong(deviceCodeTimeToLiveObj.toString())));
            }
            Object refreshTokenTimeToLiveObj = map.get(ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE);
            if (refreshTokenTimeToLiveObj != null) {
                map.put(ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE, Duration.ofSeconds(Long.parseLong(refreshTokenTimeToLiveObj.toString())));
            }
            Object idTokenSignatureAlgorithmObj = map.get(ConfigurationSettingNames.Token.ID_TOKEN_SIGNATURE_ALGORITHM);
            if (idTokenSignatureAlgorithmObj != null) {
                map.put(ConfigurationSettingNames.Token.ID_TOKEN_SIGNATURE_ALGORITHM, SignatureAlgorithm.from(idTokenSignatureAlgorithmObj.toString()));
            }
        }
        return map;
    }

}
