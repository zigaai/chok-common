package com.zigaai.security.processor.usernamepassword;

import com.zigaai.security.properties.CustomSecurityProperties;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
@EqualsAndHashCode(callSuper = true)
public class SysUsernamePasswordToken extends UsernamePasswordAuthenticationToken {

    private final CustomSecurityProperties.Context userType;

    private SysUsernamePasswordToken(Object username, Object password, CustomSecurityProperties.Context userType) {
        super(username, password);
        this.userType = userType;
    }

    private SysUsernamePasswordToken(Object username, Object password, CustomSecurityProperties.Context userType,
                                     Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.userType = userType;
    }

    public static SysUsernamePasswordToken unauthenticated(Object username, Object password, CustomSecurityProperties.Context userType) {
        return new SysUsernamePasswordToken(username, password, userType);
    }

    public static SysUsernamePasswordToken authenticated(Object username, Object password, CustomSecurityProperties.Context userType, Collection<? extends GrantedAuthority> authorities) {
        return new SysUsernamePasswordToken(username, password, userType, authorities);
    }

}
