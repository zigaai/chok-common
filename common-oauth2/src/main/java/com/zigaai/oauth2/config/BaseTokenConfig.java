package com.zigaai.oauth2.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.zigaai.constants.SecurityConstant;
import com.zigaai.oauth2.keygen.UUIDOAuth2RefreshTokenGenerator;
import com.zigaai.oauth2.service.JwtSaltValidator;
import com.zigaai.security.model.SystemUser;
import com.zigaai.security.properties.CustomSecurityProperties;
import com.zigaai.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.*;

// @Configuration
@Slf4j
@RequiredArgsConstructor
public class BaseTokenConfig {

    protected final CustomSecurityProperties securityProperties;

    private final AuthenticationService authenticationService;

    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder,
                                                            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        UUIDOAuth2RefreshTokenGenerator uuidoAuth2RefreshTokenGenerator = new UUIDOAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, uuidoAuth2RefreshTokenGenerator);
    }

    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            JwtClaimsSet.Builder claims = context.getClaims();
            SystemUser systemUser = (SystemUser) context.getPrincipal().getPrincipal();
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)
                    || context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                claims.claim(SecurityConstant.TokenKey.ID, systemUser.getId());
                claims.claim(SecurityConstant.TokenKey.USER_TYPE, systemUser.getUserType());
                String kid = encryptSalt(systemUser.getUsername(), systemUser.getSalt());
                claims.claim(SecurityConstant.TokenKey.KID, kid);
                claims.claim(SecurityConstant.TokenKey.SID, UUID.randomUUID());
                claims.claim(SecurityConstant.TokenKey.CLIENT_ID, context.getRegisteredClient().getClientId());
                claims.claim(IdTokenClaimNames.AUTH_TIME, new Date());
            }
        };
    }

    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    protected String encryptSalt(String username, String salt) {
        return DigestUtils.md5Hex(username + salt);
    }

    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
        jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgs.addAll(JWSAlgorithm.Family.EC);
        jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> jwsKeySelector =
                new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        // Override the default Nimbus claims set verifier as NimbusJwtDecoder handles it instead
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
        });
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(jwtProcessor);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(Arrays.asList(new JwtTimestampValidator(Duration.of(0, ChronoUnit.SECONDS)),
                new JwtSaltValidator(authenticationService))));
        return decoder;
    }

    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPairs = securityProperties.getKeyPairs();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPairs.getPublic())
                .privateKey(keyPairs.getPrivate())
                // .keyID(uuid)
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

}
