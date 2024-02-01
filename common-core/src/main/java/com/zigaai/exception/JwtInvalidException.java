package com.zigaai.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtInvalidException extends AuthenticationException {
    public JwtInvalidException(String message) {
        super(message);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
