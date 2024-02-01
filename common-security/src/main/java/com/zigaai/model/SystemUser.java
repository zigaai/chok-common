package com.zigaai.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.zigaai.converter.SystemUserConvertor;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;

@Getter
@ToString
@AllArgsConstructor
public class SystemUser implements UserDetails, Serializable {

    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    /**
     * id
     */
    private final Long id;

    /**
     * 用户名
     */
    private final String username;

    /**
     * 密码
     */
    @JsonIgnore
    private String password;

    /**
     * token盐值
     */
    @JsonIgnore
    private String salt;

    /**
     * 状态: 0: 正常, 1: 删除
     */
    private final Boolean isDeleted;

    /**
     * 用户类型
     */
    private final String userType;

    /**
     * 角色列表
     */
    private final List<AuthRole> roleList;

    /**
     * 页面权限
     */
    private final List<AuthMenu> menuList;

    /**
     * 权限
     */
    private final Collection<? extends GrantedAuthority> authorities;

    public static SystemUser of(AuthenticationModel admin, List<? extends AuthRole> roleList, List<? extends AuthMenu> menuList) {
        return SystemUserConvertor.INSTANCE.from(admin, roleList, menuList);
    }

    /**
     * 用户数据脱敏
     */
    public SystemUser desensitization() {
        this.password = null;
        this.salt = null;
        return this;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.isDeleted != null && !this.isDeleted;
    }
}
