package com.zigaai.exception;

import org.springframework.security.core.AuthenticationException;

public class LoginIllegalArgumentException extends AuthenticationException {

    public LoginIllegalArgumentException(String msg) {
        super(msg);
    }

}
