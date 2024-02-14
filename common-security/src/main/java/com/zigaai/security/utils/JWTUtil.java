package com.zigaai.security.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.zigaai.exception.BizIllegalArgumentException;
import com.zigaai.exception.JwtExpiredException;
import com.zigaai.exception.JwtInvalidException;
import com.zigaai.model.security.PayloadDTO;
import com.zigaai.model.security.UPMSToken;
import com.zigaai.utils.JsonUtil;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.tuple.Pair;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@UtilityClass
public final class JWTUtil {

    public static UPMSToken generateToken(PayloadDTO claims, KeyPair keyPairs) throws JsonProcessingException, JOSEException {
        Long expiresIn = claims.getExpiresIn();
        if (expiresIn == null) {
            throw new BizIllegalArgumentException("claims expiresIn cloud not be null");
        }
        Long refreshExpiresIn = claims.getRefreshExpiresIn();
        if (refreshExpiresIn == null) {
            throw new BizIllegalArgumentException("claims refreshExpiresIn cloud not be null");
        }
        // 创建JWS头，设置签名算法和类型
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).
                type(JOSEObjectType.JWT)
                .build();
        long iat = System.currentTimeMillis() / 1000;
        long exp = iat + expiresIn;
        claims.setIat(iat);
        claims.setExp(exp);
        // 将负载信息封装到Payload中
        Payload payload = new Payload(JsonUtil.toJson(claims));
        // 创建JWS对象
        JWSObject jwsObject = new JWSObject(jwsHeader, payload);
        // 创建HMAC签名器
        JWSSigner jwsSigner = new RSASSASigner(keyPairs.getPrivate());
        // 签名
        jwsObject.sign(jwsSigner);
        String tokenVal = jwsObject.serialize();
        return new UPMSToken(tokenVal, UUID.randomUUID().toString(), iat, exp, expiresIn, refreshExpiresIn);
    }

    public static Pair<JWSObject, PayloadDTO> parseUnverified(String token) throws ParseException, JsonProcessingException {
        // 从token中解析JWS对象
        JWSObject jwsObject = JWSObject.parse(token);
        // 创建HMAC验证器
        String payloadStr = jwsObject.getPayload().toString();
        PayloadDTO payloadDTO = JsonUtil.readValue(payloadStr, PayloadDTO.class);
        if (payloadDTO.getUsername() == null) {
            payloadDTO.setUsername(payloadDTO.getSub());
        }
        return Pair.of(jwsObject, payloadDTO);
    }

    public static void check(JWSObject jwsObject, PayloadDTO payload, KeyPair keyPairs) throws JOSEException {
        JWSVerifier jwsVerifier = new RSASSAVerifier((RSAPublicKey) keyPairs.getPublic());
        if (!jwsObject.verify(jwsVerifier)) {
            throw new JwtInvalidException("token签名不合法, 请重新登录");
        }
        if (TimeUnit.SECONDS.toMillis(payload.getExp()) < new Date().getTime()) {
            throw new JwtExpiredException("token已过期, 请重新登录");
        }
    }

}
