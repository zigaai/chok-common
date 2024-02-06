package com.zigaai.oauth2.handler;

import com.zigaai.model.common.ResponseData;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * OAuth2 认证错误处理
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthorizationErrorHandler implements AuthenticationFailureHandler {

    private final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.warn("OAuth2 认证错误", exception);
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2Error oAuth2Error = ((OAuth2AuthenticationException) exception).getError();
            String msg = StringUtils.hasText(oAuth2Error.getDescription()) ? String.format("%s: %s", oAuth2Error.getDescription(), oAuth2Error.getErrorCode()) : oAuth2Error.getErrorCode();
            jackson2HttpMessageConverter.write(ResponseData.badRequest(msg), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
            return;
        }
        jackson2HttpMessageConverter.write(ResponseData.badRequest(exception.getLocalizedMessage()), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }

}
