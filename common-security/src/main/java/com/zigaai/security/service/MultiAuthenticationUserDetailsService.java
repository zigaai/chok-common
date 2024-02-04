package com.zigaai.security.service;

import com.zigaai.strategy.Strategy;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface MultiAuthenticationUserDetailsService extends UserDetailsService, Strategy<String> {

}