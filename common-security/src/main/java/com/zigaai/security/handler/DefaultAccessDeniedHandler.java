package com.zigaai.security.handler;

import com.zigaai.model.common.ResponseData;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

/**
 * 当访问接口没有权限时，自定义的返回结果
 */
// @Component
@RequiredArgsConstructor
public class DefaultAccessDeniedHandler implements AccessDeniedHandler {

    private final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        jackson2HttpMessageConverter.write(ResponseData.forbidden("当前用户无权访问, 请联系管理员"), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }

}
