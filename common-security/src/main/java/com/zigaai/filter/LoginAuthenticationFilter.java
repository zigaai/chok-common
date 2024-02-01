package com.zigaai.filter;

import com.nimbusds.jose.JOSEException;
import com.zigaai.converter.SystemUserConvertor;
import com.zigaai.enumeration.LoginType;
import com.zigaai.enumeration.ResponseState;
import com.zigaai.exception.LoginException;
import com.zigaai.exception.LoginIllegalArgumentException;
import com.zigaai.model.PayloadDTO;
import com.zigaai.model.SystemUser;
import com.zigaai.model.UPMSToken;
import com.zigaai.model.common.ResponseData;
import com.zigaai.processor.LoginProcessor;
import com.zigaai.properties.CustomSecurityProperties;
import com.zigaai.strategy.StrategyFactory;
import com.zigaai.utils.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
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

    private final RedisTemplate<String, Object> redisTemplate;

    public LoginAuthenticationFilter(StrategyFactory<LoginType, LoginProcessor> loginTypeLoginProcessorStrategy,
                                     AuthenticationManager authenticationManager,
                                     CustomSecurityProperties securityProperties,
                                     MappingJackson2HttpMessageConverter jackson2HttpMessageConverter,
                                     RedisTemplate<String, Object> redisTemplate) {
        super(LOGIN_REQUEST_MATCHER);
        super.setAuthenticationManager(authenticationManager);
        this.loginTypeLoginProcessorStrategy = loginTypeLoginProcessorStrategy;
        this.securityProperties = securityProperties;
        this.jackson2HttpMessageConverter = jackson2HttpMessageConverter;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // LoginDTO params = (LoginDTO) jackson2HttpMessageConverter.read(LoginDTO.class, new ServletServerHttpRequest(request));
        // TODO tenant 租户
        LoginType loginType = obtainLoginType(request);
        Authentication unauthenticated = loginTypeLoginProcessorStrategy.getStrategy(loginType).buildUnauthenticated(request);
        return this.getAuthenticationManager().authenticate(unauthenticated);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        SystemUser systemUser = (SystemUser) authResult.getPrincipal();
        PayloadDTO payload = SystemUserConvertor.INSTANCE.toPayloadDTO(systemUser, securityProperties.getToken().getTimeToLive(), securityProperties.getToken().getRefreshTimeToLive());
        UPMSToken upmsToken;
        try {
            upmsToken = JWTUtil.generateToken(payload, systemUser.getSalt());
        } catch (JOSEException e) {
            log.error("生成token错误: ", e);
            jackson2HttpMessageConverter.write(ResponseData.unknownError("生成token错误"), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
            return;
        }
        this.cacheRefreshToken(upmsToken, payload);
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

    protected LoginType obtainLoginType(HttpServletRequest request) {
        String loginTypeStr = request.getParameter("loginType");
        if (StringUtils.isBlank(loginTypeStr)) {
            throw new LoginIllegalArgumentException("登录类型为空");
        }
        LoginType loginType;
        try {
            loginType = LoginType.getByVal(Byte.parseByte(loginTypeStr));
        } catch (NumberFormatException e) {
            throw new LoginIllegalArgumentException("非法的登录类型");
        }
        if (loginType == null) {
            throw new LoginIllegalArgumentException("暂不支持类型: " + loginTypeStr);
        }
        return loginType;
    }

    protected void cacheRefreshToken(UPMSToken upmsToken, PayloadDTO payload) {
        // TODO
        // long refreshTimeToLive = upmsToken.getRefreshExpiresIn();
        // String refreshToken = upmsToken.getRefreshToken();
        // String refreshTokenKey = RedisConstant.REFRESH_TOKEN(refreshToken);
        // String userRefreshTokensKey = RedisConstant.USER_REFRESH_TOKEN(payload.getUserType(), payload.getUsername());
        // redisTemplate.execute((RedisCallback<Integer>) connection -> {
        //     HashSet<String> refreshTokens = deserializeVal(connection.stringCommands().get(serializeKey(userRefreshTokensKey)));
        //     if (CollectionUtils.isEmpty(refreshTokens)) {
        //         refreshTokens = new HashSet<>();
        //     }
        //     refreshTokens.add(refreshToken);
        //     ImmutableMap<String, Object> map = ImmutableMap
        //             .<String, Object>builder()
        //             .put(refreshTokenKey, payload)
        //             .put(userRefreshTokensKey, refreshTokens)
        //             .build();
        //     return multiSet(connection, map, refreshTimeToLive);
        // });
    }

}
