package com.zigaai.security.filter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.zigaai.exception.JwtExpiredException;
import com.zigaai.model.security.PayloadDTO;
import com.zigaai.security.model.SystemUser;
import com.zigaai.security.properties.CustomSecurityProperties;
import com.zigaai.security.service.MultiAuthenticationUserDetailsService;
import com.zigaai.security.utils.JWTUtil;
import com.zigaai.security.utils.SecurityUtil;
import com.zigaai.strategy.StrategyFactory;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.CollectionUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.HashSet;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final StrategyFactory<String, MultiAuthenticationUserDetailsService> userDetailsServiceStrategy;

    private final CustomSecurityProperties securityProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (securityProperties.getIgnoreUrls().contains(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }
        String token = SecurityUtil.getTokenVal(request);
        if (StringUtils.isBlank(token)) {
            chain.doFilter(request, response);
            return;
        }
        SystemUser systemUser;
        try {
            Pair<JWSObject, PayloadDTO> pair = JWTUtil.parseUnverified(token);
            PayloadDTO payload = pair.getRight();
            // TODO 接口化
            systemUser = (SystemUser) userDetailsServiceStrategy.getStrategy(payload.getUserType()).loadUserByUsername(payload.getUsername());
            JWTUtil.check(pair.getLeft(), payload, securityProperties.getKeyPairs());
        } catch (ParseException | JOSEException | JwtExpiredException e) {
            log.info("解析token失败: ", e);
            chain.doFilter(request, response);
            return;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.info("解密token失败: ", e);
            chain.doFilter(request, response);
            return;
        }
        if (SecurityContextHolder.getContext().getAuthentication() == null
                || SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken
        ) {
            Authentication jwtAuthentication = SecurityContextHolder.getContext().getAuthentication();
            if (jwtAuthentication != null) {
                Jwt jwt = (Jwt) jwtAuthentication.getPrincipal();
                String clientId = jwt.getClaimAsString("clientId");
                if (clientId != null) {
                    systemUser.setClientId(clientId);
                }
                List<String> audList = jwt.getClaimAsStringList("aud");
                if (!CollectionUtils.isEmpty(audList)) {
                    systemUser.setAud(new HashSet<>(audList));
                }
                List<String> scopeList = jwt.getClaimAsStringList("scope");
                if (!CollectionUtils.isEmpty(scopeList)) {
                    systemUser.setScope(new HashSet<>(scopeList));
                }
            }
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(systemUser, null, systemUser.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }

}
