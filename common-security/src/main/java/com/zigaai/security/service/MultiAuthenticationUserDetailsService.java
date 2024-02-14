package com.zigaai.security.service;

import com.zigaai.strategy.Strategy;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface MultiAuthenticationUserDetailsService extends UserDetailsService, Strategy<String> {

    default String getSaltByUsername(String username) {
        return StringUtils.EMPTY;
    }

}
