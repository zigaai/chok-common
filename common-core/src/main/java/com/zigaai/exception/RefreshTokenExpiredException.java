package com.zigaai.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * refresh token 过期异常
 */
public class RefreshTokenExpiredException extends AuthenticationException {

    public RefreshTokenExpiredException(String message) {
        super(message);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }

}
