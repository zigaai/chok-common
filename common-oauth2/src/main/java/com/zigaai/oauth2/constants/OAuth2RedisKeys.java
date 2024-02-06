package com.zigaai.oauth2.constants;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

public final class OAuth2RedisKeys {

    private OAuth2RedisKeys() {
    }

    public static final String OAUTH2_PREFIX = "oauth2:";

    public static final String AUTHORIZATION_CODE(String key) {
        return OAUTH2_PREFIX + AuthorizationGrantType.AUTHORIZATION_CODE.getValue() + ":" + key;
    }

    public static final String ACCESS_TOKEN(String key) {
        return OAUTH2_PREFIX + OAuth2ParameterNames.ACCESS_TOKEN + ":" + key;
    }

    public static final String RESOURCE_PRINCIPAL(String principalName, String authorizationId) {
        return OAUTH2_PREFIX + "principal:" + principalName + ":" + authorizationId;
    }

    public static final String REFRESH_TOKEN(String key) {
        return OAUTH2_PREFIX + OAuth2ParameterNames.REFRESH_TOKEN + ":" + key;
    }

    // public static final Function<String, String> REL_ACCESS_TOKEN_REFRESH_TOKEN = key -> OAUTH2_PREFIX + OAuth2ParameterNames.ACCESS_TOKEN + "_to_" + OAuth2ParameterNames.REFRESH_TOKEN + ":" + key;

    public static final String OIDC_TOKEN(String key) {
        return OAUTH2_PREFIX + "oidc_token:" + key;
    }

    public static final String OAUTH2_STATE_CODE(String key) {
        return OAUTH2_PREFIX + OAuth2ParameterNames.STATE + ":" + key;
    }

    public static final String OAUTH2_AUTHORIZATION(String key) {
        return OAUTH2_PREFIX + "authorization:" + key;
    }

    public static final String OAUTH2_REGISTERED_CLIENT(String key) {
        return OAUTH2_PREFIX + "client:" + key;
    }

    public static final String OAUTH2_REGISTERED_CLIENT_ID(String key) {
        return OAUTH2_PREFIX + "client_id:" + key;
    }

}
