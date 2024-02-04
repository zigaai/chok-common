package com.zigaai.model.security;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@Setter
@ToString
public class AuthRole implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 角色编码
     */
    protected String roleCode;

}
