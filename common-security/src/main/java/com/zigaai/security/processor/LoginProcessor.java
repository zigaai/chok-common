package com.zigaai.security.processor;

import com.zigaai.security.model.LoginDTO;
import com.zigaai.security.enumeration.LoginType;
import com.zigaai.strategy.Strategy;
import org.springframework.security.core.Authentication;

public interface LoginProcessor extends Strategy<LoginType> {

    Authentication buildUnauthenticated(LoginDTO params);

}
