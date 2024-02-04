package com.zigaai.model.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@Setter
@ToString
public class PayloadDTO implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * id
     */
    private Long id;

    /**
     * 用户名
     */
    private String username;

    /**
     * 用户类型
     */
    private String userType;

    /**
     * 过期时间
     */
    private Long exp;

    /**
     * 签发时间
     */
    private Long iat;

    /**
     * refresh token 持续时间
     */
    @JsonIgnore
    private Long expiresIn;

    // @JsonIgnore
    // private String salt;

    /**
     * refresh token 持续时间
     */
    @JsonIgnore
    private Long refreshExpiresIn;
}
