package com.zigaai.properties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

@Getter
@Setter
@ToString
@ConfigurationProperties(prefix = "security")
public class CustomSecurityProperties {

    /**
     * 忽略鉴权路径
     */
    private Set<String> ignoreUrls;


    /**
     * token 配置
     */
    private Token token;

    /**
     * RSA配置
     */
    private RSA rsa;

    /**
     * 配置用户类型
     */
    private Map<String, Context> userType;

    public Context getUserType(String code) {
        return userType.get(code);
    }

    @Getter
    @Setter
    @ToString
    public static class Context {

        /**
         * 用户类型值
         */
        private Byte val;

        /**
         * 用户类型code
         */
        private String code;

        /**
         * 用户角色关联表表名
         */
        private String relationTable;

        /**
         * 用户角色关联表关联ID
         */
        private String relationId;
    }

    @Getter
    @Setter
    @ToString
    public static class Token {

        /**
         * 登录token过期时间
         */
        private Long timeToLive = 3600L;

        /**
         * refresh token 过期时间
         */
        private Long refreshTimeToLive = 604800L;
    }

    /**
     * RSA非对称密钥
     */
    @Getter
    @Setter
    @ToString
    public static class RSA {

        /**
         * 公钥
         */
        private String publicKey;

        /**
         * 私钥
         */
        private String privateKey;

        private KeyPair keyPair;
    }

    public KeyPair getKeyPairs() throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (StringUtils.isBlank(this.rsa.privateKey) || StringUtils.isBlank(this.rsa.publicKey)) {
            return null;
        }
        if (this.rsa.keyPair != null) {
            return this.rsa.keyPair;
        }
        // 将Base64编码的公钥和私钥字符串转换为字节数组
        byte[] publicKeyBytes = Base64.getDecoder().decode(this.rsa.publicKey);
        byte[] privateKeyBytes = Base64.getDecoder().decode(this.rsa.privateKey);

        // 使用X.509和PKCS8密钥规范创建公钥和私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        this.rsa.keyPair = keyPair;
        return keyPair;
    }
}
