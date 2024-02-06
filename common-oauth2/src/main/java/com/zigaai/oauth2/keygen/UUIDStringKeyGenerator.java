package com.zigaai.oauth2.keygen;

import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * UUID生成器
 */
@Component
public class UUIDStringKeyGenerator implements StringKeyGenerator {
    @Override
    public String generateKey() {
        return UUID.randomUUID().toString();
    }
}
