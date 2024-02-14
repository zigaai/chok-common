package com.zigaai.security.filter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.zigaai.exception.JwtExpiredException;
import com.zigaai.model.security.PayloadDTO;
import com.zigaai.security.model.SystemUser;
import com.zigaai.security.service.AuthenticationService;
import com.zigaai.security.utils.JWTUtil;
import com.zigaai.security.utils.SecurityUtil;
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
import java.security.KeyPair;
import java.text.ParseException;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final AuthenticationService authenticationService;

    private final Collection<String> ignoreUrls;

    private final KeyPair rsaKeyPair;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (!CollectionUtils.isEmpty(this.ignoreUrls)
                && this.ignoreUrls.contains(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }
        String token = SecurityUtil.getTokenVal(request);
        if (StringUtils.isBlank(token)) {
            chain.doFilter(request, response);
            return;
        }
        Authentication jwtAuthentication = SecurityContextHolder.getContext().getAuthentication();
        SystemUser systemUser;
        try {
            Pair<JWSObject, PayloadDTO> pair = JWTUtil.parseUnverified(token);
            PayloadDTO payload = pair.getRight();
            systemUser = authenticationService.loadUserByUsername(payload.getUserType(), payload.getUsername());
            if (jwtAuthentication instanceof JwtAuthenticationToken) {
                this.fillByJWT(jwtAuthentication, systemUser);
            } else {
                JWTUtil.check(pair.getLeft(), payload, this.rsaKeyPair);
            }
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(systemUser, null, systemUser.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (ParseException | JOSEException | JwtExpiredException e) {
            log.info("解析token失败: ", e);
            chain.doFilter(request, response);
            return;
        }
        chain.doFilter(request, response);
    }

    private void fillByJWT(Authentication jwtAuthentication, SystemUser systemUser) {
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

}
