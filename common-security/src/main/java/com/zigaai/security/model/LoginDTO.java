package com.zigaai.security.model;

import com.zigaai.exception.LoginIllegalArgumentException;
import com.zigaai.security.properties.CustomSecurityProperties;
import io.micrometer.common.util.StringUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@Setter
@ToString
public class LoginDTO implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 用户名
     */
    private String username;

    /**
     * 密码(加密后)
     */
    private String password;

    /**
     * 登录类型:
     * 1: 用户名密码登录
     * 2: 手机号验证码登录
     */
    private Byte loginType;

    /**
     * 用户类型:
     * admin: 管理员
     * user: 普通用户
     */
    private String userType;

    public void validateByUsernamePassword(CustomSecurityProperties securityProperties) {
        if (StringUtils.isBlank(this.username)) {
            throw new LoginIllegalArgumentException("请输入用户名");
        }
        if (StringUtils.isBlank(this.password)) {
            throw new LoginIllegalArgumentException("请输入密码");
        }
        if (StringUtils.isBlank(this.userType)) {
            throw new LoginIllegalArgumentException("请选择用户类型");
        }
        CustomSecurityProperties.Context userType = securityProperties.getUserType(this.userType);
        if (userType == null) {
            throw new LoginIllegalArgumentException("非法的用户类型");
        }
    }
}
