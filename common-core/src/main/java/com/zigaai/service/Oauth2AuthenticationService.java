package com.zigaai.service;

public interface Oauth2AuthenticationService {

    String getSaltByUsername(String userType, String username);

}
