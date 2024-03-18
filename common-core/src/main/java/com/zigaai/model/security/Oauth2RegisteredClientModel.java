package com.zigaai.model.security;

import java.util.Date;

public interface Oauth2RegisteredClientModel {

    String getClientId();

    String getClientSecret();

    Date getClientIdIssuedAt();

    String getClientName();

    String getClientAuthenticationMethods();

    String getAuthorizationGrantTypes();

    String getRedirectUris();

    String getScopes();

    Date getClientSecretExpiresAt();

    String getClientSettings();

    String getTokenSettings();

    String getPostLogoutRedirectUris();

}
