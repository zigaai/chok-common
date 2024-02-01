package com.zigaai.processor;

import com.zigaai.enumeration.LoginType;
import com.zigaai.strategy.Strategy;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface LoginProcessor extends Strategy<LoginType> {

    Authentication buildUnauthenticated(HttpServletRequest request);

}
