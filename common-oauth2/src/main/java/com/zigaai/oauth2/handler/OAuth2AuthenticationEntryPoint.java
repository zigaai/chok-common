package com.zigaai.oauth2.handler;

import com.zigaai.model.common.ResponseData;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        log.warn("OAuth2 认证错误: ", e);
        jackson2HttpMessageConverter.write(ResponseData.unauthorized("OAuth2 认证错误"), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }
}
