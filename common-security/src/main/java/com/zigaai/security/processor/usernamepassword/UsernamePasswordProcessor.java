package com.zigaai.security.processor.usernamepassword;

import com.zigaai.security.model.LoginDTO;
import com.zigaai.security.enumeration.LoginType;
import com.zigaai.exception.LoginException;
import com.zigaai.security.processor.LoginProcessor;
import com.zigaai.security.properties.CustomSecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.util.Base64;

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
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, securityProperties.getKeyPairs().getPrivate());
            byte[] decryptedBytes = decryptCipher.doFinal(Base64.getDecoder().decode(params.getPassword()));
            originPass = new String(decryptedBytes);
        } catch (Exception e) {
            throw new LoginException("密码解密错误");
        }
        return SysUsernamePasswordToken.unauthenticated(params.getUsername(), originPass, userType);
    }
}
