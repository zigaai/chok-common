package com.zigaai.security.properties;

import cn.hutool.crypto.SecureUtil;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.io.Serial;
import java.io.Serializable;
import java.security.KeyPair;
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
     * RSA实例
     */
    cn.hutool.crypto.asymmetric.RSA rsaInstance;

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
    public static class Context implements Serializable {

        @Serial
        private static final long serialVersionUID = 1L;

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

    public KeyPair getKeyPairs() {
        if (StringUtils.isBlank(this.rsa.privateKey) || StringUtils.isBlank(this.rsa.publicKey)) {
            return null;
        }
        if (this.rsa.keyPair != null) {
            return this.rsa.keyPair;
        }
        if (rsaInstance == null) {
            rsaInstance = SecureUtil.rsa(this.rsa.privateKey, this.rsa.publicKey);
        }
        this.rsa.keyPair = new KeyPair(rsaInstance.getPublicKey(), rsaInstance.getPrivateKey());
        return this.rsa.keyPair;
    }

    public cn.hutool.crypto.asymmetric.RSA getRsaInstance() {
        if (rsaInstance == null) {
            rsaInstance = SecureUtil.rsa(this.rsa.privateKey, this.rsa.publicKey);
        }
        return this.rsaInstance;
    }

}
