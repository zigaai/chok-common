package com.zigaai.security.service;

import com.zigaai.security.model.SystemUser;

public interface AuthenticationService {

    String getSalt(String userType, String username);

    SystemUser loadUserByUsername(String userType, String username);

}
