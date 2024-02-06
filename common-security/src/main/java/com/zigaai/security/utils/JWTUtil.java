package com.zigaai.security.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.zigaai.exception.BizIllegalArgumentException;
import com.zigaai.exception.JwtExpiredException;
import com.zigaai.exception.JwtInvalidException;
import com.zigaai.model.security.PayloadDTO;
import com.zigaai.model.security.UPMSToken;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.zigaai.utils.JsonUtil;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.tuple.Pair;

import java.text.ParseException;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@UtilityClass
public final class JWTUtil {

    public static UPMSToken generateToken(PayloadDTO claims, String salt) throws JsonProcessingException, JOSEException {
        Long expiresIn = claims.getExpiresIn();
        if (expiresIn == null) {
            throw new BizIllegalArgumentException("claims expiresIn cloud not be null");
        }
        Long refreshExpiresIn = claims.getRefreshExpiresIn();
        if (refreshExpiresIn == null) {
            throw new BizIllegalArgumentException("claims refreshExpiresIn cloud not be null");
        }
        // 创建JWS头，设置签名算法和类型
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.HS256).
                type(JOSEObjectType.JWT)
                .build();
        long iat = System.currentTimeMillis();
        long exp = iat + TimeUnit.SECONDS.toMillis(expiresIn);
        claims.setIat(iat);
        claims.setExp(exp);
        // 将负载信息封装到Payload中
        Payload payload = new Payload(JsonUtil.toJson(claims));
        // 创建JWS对象
        JWSObject jwsObject = new JWSObject(jwsHeader, payload);
        // 创建HMAC签名器
        JWSSigner jwsSigner = new MACSigner(generateSecret(claims.getId(), salt));
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

    // public static PayloadDTO parseVerified(String token, String salt) throws ParseException, JsonProcessingException, JOSEException {
    //     Pair<JWSObject, PayloadDTO> pair = parseUnverified(token);
    //     JWSObject jwsObject = pair.getLeft();
    //     PayloadDTO payload = pair.getRight();
    //     payload.setSalt(salt);
    //     check(jwsObject, payload);
    //     return payload;
    // }

    public static void check(JWSObject jwsObject, PayloadDTO payload, String salt) throws JOSEException {
        JWSVerifier jwsVerifier = new MACVerifier(generateSecret(payload.getId(), salt));
        if (!jwsObject.verify(jwsVerifier)) {
            throw new JwtInvalidException("token签名不合法, 请重新登录");
        }
        if (payload.getExp() < new Date().getTime()) {
            throw new JwtExpiredException("token已过期, 请重新登录");
        }
    }

    private static String generateSecret(Long userId, String salt) {
        return userId + salt;
    }

}
