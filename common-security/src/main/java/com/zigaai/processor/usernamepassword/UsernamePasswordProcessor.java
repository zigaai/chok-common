package com.zigaai.processor.usernamepassword;

import com.zigaai.enumeration.LoginType;
import com.zigaai.exception.LoginException;
import com.zigaai.exception.LoginIllegalArgumentException;
import com.zigaai.processor.LoginProcessor;
import com.zigaai.properties.CustomSecurityProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
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
    public Authentication buildUnauthenticated(HttpServletRequest request) {
        String username = request.getParameter("username");
        String userTypeStr = request.getParameter("userType");
        if (StringUtils.isBlank(userTypeStr)) {
            throw new LoginIllegalArgumentException("用户类型不可为空");
        }
        CustomSecurityProperties.Context userType;
        try {
            userType =  securityProperties.getUserType(userTypeStr);
        } catch (NumberFormatException e) {
            throw new LoginIllegalArgumentException("非法的用户类型");
        }
        if (StringUtils.isBlank(username)) {
            throw new LoginIllegalArgumentException("请输入用户名");
        }
        String password = request.getParameter("password");
        if (StringUtils.isBlank(password)) {
            throw new LoginIllegalArgumentException("请输入密码");
        }
        String originPass;
        try {
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, securityProperties.getKeyPairs().getPrivate());
            byte[] decryptedBytes = decryptCipher.doFinal(Base64.getDecoder().decode(password));
            originPass = new String(decryptedBytes);
        } catch (Exception e) {
            throw new LoginException("密码解密错误");
        }
        return SysUsernamePasswordToken.unauthenticated(username, originPass, userType);
    }
}
