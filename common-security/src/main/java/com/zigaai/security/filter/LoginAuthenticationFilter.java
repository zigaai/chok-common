package com.zigaai.security.filter;

import com.nimbusds.jose.JOSEException;
import com.zigaai.enumeration.ResponseState;
import com.zigaai.exception.LoginException;
import com.zigaai.exception.LoginIllegalArgumentException;
import com.zigaai.model.common.ResponseData;
import com.zigaai.model.security.PayloadDTO;
import com.zigaai.model.security.UPMSToken;
import com.zigaai.security.converter.SystemUserConvertor;
import com.zigaai.security.enumeration.LoginType;
import com.zigaai.security.model.LoginDTO;
import com.zigaai.security.model.SystemUser;
import com.zigaai.security.processor.LoginProcessor;
import com.zigaai.security.properties.CustomSecurityProperties;
import com.zigaai.security.service.TokenCacheService;
import com.zigaai.security.utils.JWTUtil;
import com.zigaai.strategy.StrategyFactory;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;

@Slf4j
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final RequestMatcher LOGIN_REQUEST_MATCHER = new AntPathRequestMatcher("/login", "POST");

    private final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;

    private final StrategyFactory<LoginType, LoginProcessor> loginTypeLoginProcessorStrategy;

    private final CustomSecurityProperties securityProperties;
    private final TokenCacheService tokenCacheService;

    public LoginAuthenticationFilter(StrategyFactory<LoginType, LoginProcessor> loginTypeLoginProcessorStrategy,
                                     AuthenticationManager authenticationManager,
                                     CustomSecurityProperties securityProperties,
                                     MappingJackson2HttpMessageConverter jackson2HttpMessageConverter,
                                     TokenCacheService tokenCacheService) {
        super(LOGIN_REQUEST_MATCHER);
        super.setAuthenticationManager(authenticationManager);
        this.loginTypeLoginProcessorStrategy = loginTypeLoginProcessorStrategy;
        this.securityProperties = securityProperties;
        this.jackson2HttpMessageConverter = jackson2HttpMessageConverter;
        this.tokenCacheService = tokenCacheService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        LoginDTO params = (LoginDTO) jackson2HttpMessageConverter.read(LoginDTO.class, new ServletServerHttpRequest(request));
        // TODO tenant 租户 //NOSONAR
        LoginType loginType = LoginType.getByVal(params.getLoginType());
        LoginProcessor processor = loginTypeLoginProcessorStrategy.getStrategy(loginType);
        if (processor == null) {
            throw new LoginIllegalArgumentException("不支持此登录类型登录");
        }
        Authentication unauthenticated = processor.buildUnauthenticated(params);
        return this.getAuthenticationManager().authenticate(unauthenticated);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        SystemUser systemUser = (SystemUser) authResult.getPrincipal();
        PayloadDTO payload = SystemUserConvertor.INSTANCE.toPayloadDTO(systemUser, securityProperties.getToken().getTimeToLive(), securityProperties.getToken().getRefreshTimeToLive());
        UPMSToken upmsToken;
        try {
            upmsToken = JWTUtil.generateToken(payload, securityProperties.getKeyPairs());
        } catch (JOSEException e) {
            log.error("生成token错误: ", e);
            jackson2HttpMessageConverter.write(ResponseData.unknownError("生成token错误"), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
            return;
        }
        tokenCacheService.cacheRefreshToken(upmsToken, payload);
        jackson2HttpMessageConverter.write(ResponseData.success("登录成功", upmsToken), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        String msg = ResponseState.UNKNOWN_ERROR.getMsg();
        if (failed instanceof LoginIllegalArgumentException
                || failed instanceof BadCredentialsException
                || failed instanceof UsernameNotFoundException
                || failed instanceof LoginException) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            msg = failed.getMessage();
        }
        if (failed instanceof DisabledException) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            msg = failed.getMessage();
        }
        jackson2HttpMessageConverter.write(ResponseData.badRequest(msg), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }

}
