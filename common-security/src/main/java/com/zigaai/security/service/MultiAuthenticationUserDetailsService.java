package com.zigaai.security.service;

import com.zigaai.strategy.Strategy;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface MultiAuthenticationUserDetailsService extends UserDetailsService, Strategy<String> {

    default String getSalt(String username) {
        return StringUtils.EMPTY;
    }

    default void updateSalt(String username) {
    }

}
