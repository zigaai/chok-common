package com.zigaai.model.security;

import java.util.Date;
import java.util.Map;

public interface Oauth2RegisteredClientModel {

    Long getId();

    String getClientId();

    String getClientSecret();

    Date getClientIdIssuedAt();

    String getClientName();

    String getClientAuthenticationMethods();

    String getAuthorizationGrantTypes();

    String getRedirectUris();

    String getScopes();

    Date getClientSecretExpiresAt();

    Map<String, Object> parseClientSettings();

    Map<String, Object> parseTokenSettings();

    String getPostLogoutRedirectUris();

}
