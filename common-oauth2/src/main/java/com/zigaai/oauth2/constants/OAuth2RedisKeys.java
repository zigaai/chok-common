package com.zigaai.oauth2.constants;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

public final class OAuth2RedisKeys {

    private OAuth2RedisKeys() {
    }

    public static final String OAUTH2_PREFIX = "oauth2:";

    @SuppressWarnings("squid:S100")
    public static String AUTHORIZATION_CODE(String key) {
        return OAUTH2_PREFIX + AuthorizationGrantType.AUTHORIZATION_CODE.getValue() + ":" + key;
    }

    @SuppressWarnings("squid:S100")
    public static String ACCESS_TOKEN(String key) {
        return OAUTH2_PREFIX + OAuth2ParameterNames.ACCESS_TOKEN + ":" + key;
    }

    @SuppressWarnings("squid:S100")
    public static String RESOURCE_PRINCIPAL(String principalName, String authorizationId) {
        return OAUTH2_PREFIX + "principal:" + principalName + ":" + authorizationId;
    }

    @SuppressWarnings("squid:S100")
    public static String REFRESH_TOKEN(String key) {
        return OAUTH2_PREFIX + OAuth2ParameterNames.REFRESH_TOKEN + ":" + key;
    }

    @SuppressWarnings("squid:S100")
    public static String OIDC_TOKEN(String key) {
        return OAUTH2_PREFIX + "oidc_token:" + key;
    }

    @SuppressWarnings("squid:S100")
    public static String OAUTH2_STATE_CODE(String key) {
        return OAUTH2_PREFIX + OAuth2ParameterNames.STATE + ":" + key;
    }

    @SuppressWarnings("squid:S100")
    public static String OAUTH2_AUTHORIZATION(String key) {
        return OAUTH2_PREFIX + "authorization:" + key;
    }

    @SuppressWarnings("squid:S100")
    public static String OAUTH2_REGISTERED_CLIENT(String key) {
        return OAUTH2_PREFIX + "client:" + key;
    }

    @SuppressWarnings("squid:S100")
    public static String OAUTH2_REGISTERED_CLIENT_ID(String key) {
        return OAUTH2_PREFIX + "client_id:" + key;
    }

}
