package com.zigaai.model.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@ToString
@RequiredArgsConstructor
public class UPMSToken implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * access token
     */
    private final String accessToken;

    /**
     * refresh token
     */
    private final String refreshToken;

    /**
     * 签发时间
     */
    private final Long iat;

    /**
     * 过期时间
     */
    private final Long exp;

    /**
     * access token 过期时间/秒
     */
    private final long expiresIn;

    /**
     * refresh token 过期时间/秒
     */
    private final long refreshExpiresIn;

}
