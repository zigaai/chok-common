package com.zigaai.security.model;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.zigaai.model.security.AuthMenu;
import com.zigaai.model.security.AuthRole;
import com.zigaai.security.serializers.SimpleGrantedAuthorityDeserializer;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;

@Getter
@Setter
@ToString
public class SystemUserVO implements Serializable {

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
     * 状态: 0: 正常, 1: 删除
     */
    private Boolean isDeleted;

    /**
     * 用户类型
     */
    private String userType;

    /**
     * 角色列表
     */
    private List<? extends AuthRole> roleList;

    /**
     * 页面权限
     */
    private List<? extends AuthMenu> menuList;

    /**
     * 权限
     */
    @JsonDeserialize(using = SimpleGrantedAuthorityDeserializer.class)
    private Collection<? extends GrantedAuthority> authorities;
}
