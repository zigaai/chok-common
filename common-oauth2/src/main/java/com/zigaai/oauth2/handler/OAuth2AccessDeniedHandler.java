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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AccessDeniedHandler implements AccessDeniedHandler {

    private final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        log.warn("OAuth2.0 无权访问", e);
        jackson2HttpMessageConverter.write(ResponseData.forbidden("OAuth2 错误: 用户无权访问"), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }
}
