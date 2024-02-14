package com.zigaai.security.processor.usernamepassword;

import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import com.zigaai.exception.LoginException;
import com.zigaai.security.enumeration.LoginType;
import com.zigaai.security.model.LoginDTO;
import com.zigaai.security.processor.LoginProcessor;
import com.zigaai.security.properties.CustomSecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UsernamePasswordProcessor implements LoginProcessor {

    private final CustomSecurityProperties securityProperties;

    @Override
    public LoginType getKey() {
        return LoginType.USERNAME_PASSWORD;
    }


    @Override
    public Authentication buildUnauthenticated(LoginDTO params) {
        params.validateByUsernamePassword(securityProperties);
        CustomSecurityProperties.Context userType = securityProperties.getUserType(params.getUserType());
        String originPass;
        try {
            RSA rsa = securityProperties.getRsaInstance();
            originPass = rsa.decryptStr(params.getPassword(), KeyType.PrivateKey);
        } catch (Exception e) {
            throw new LoginException("密码解密错误");
        }
        return SysUsernamePasswordToken.unauthenticated(params.getUsername(), originPass, userType);
    }
}
