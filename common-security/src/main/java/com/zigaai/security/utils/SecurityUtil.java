package com.zigaai.security.utils;

import com.zigaai.constants.SecurityConstant;
import com.zigaai.model.security.AuthMenu;
import com.zigaai.model.security.AuthRole;
import com.zigaai.security.model.SystemUser;
import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.CollectionUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@UtilityClass
public final class SecurityUtil {

    public static SystemUser currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new AuthenticationCredentialsNotFoundException("用户未登录, 请重新登录");
        }
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof SystemUser currentUser)) {
            throw new AuthenticationCredentialsNotFoundException("用户未登录或登录已过期, 请重新登录");
        }
        return currentUser;
    }

    public static Set<SimpleGrantedAuthority> toAuthorities(List<? extends AuthRole> roleList, List<? extends AuthMenu> menuList) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        if (!CollectionUtils.isEmpty(roleList)) {
            for (AuthRole role : roleList) {
                authorities.add(new SimpleGrantedAuthority(role.getRoleCode()));
            }
        }
        if (!CollectionUtils.isEmpty(menuList)) {
            for (AuthMenu permission : menuList) {
                authorities.add(new SimpleGrantedAuthority(permission.getName()));
            }
        }
        return authorities;
    }

    public static String getTokenVal(HttpServletRequest request) {
        String token = request.getHeader(SecurityConstant.PRE_AUTHORIZATION_HEADER);
        if (StringUtils.isBlank(token)) {
            token = request.getHeader(HttpHeaders.AUTHORIZATION);
        }
        String prefix = SecurityConstant.TOKEN_PREFIX;
        if (StringUtils.isBlank(token) || !token.startsWith(prefix)) {
            return null;
        }
        return token.substring(prefix.length());
    }
}
