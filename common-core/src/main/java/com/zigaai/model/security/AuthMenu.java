package com.zigaai.model.security;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@Setter
@ToString
public class AuthMenu implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 权限名: 	路由命名规则: AaBbCc, 	按钮权限命名规则: a-b-btn, 	特殊权限命名规则: a:b:c
     */
    protected String name;

}
