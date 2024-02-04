package com.zigaai.model.security;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@Setter
@ToString
public class AuthAdmin implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    protected Long id;

    /**
     * 用户名
     */
    protected String username;

    /**
     * 密码
     */
    protected String password;

    /**
     * 盐值
     */
    protected String salt;

    /**
     * 状态: 	0: 正常 	1: 删除
     */
    private Boolean isDeleted;
}
