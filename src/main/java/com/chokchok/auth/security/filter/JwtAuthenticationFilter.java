package com.chokchok.auth.security.filter;

import com.chokchok.auth.common.exception.base.InvalidException;
import com.chokchok.auth.common.exception.code.ErrorCode;
import com.chokchok.auth.config.RedisHashKey;
import com.chokchok.auth.dto.req.LoginRequestDto;
import com.chokchok.auth.dto.res.TokenResponseDto;
import com.chokchok.auth.jwt.JwtFailureHandler;
import com.chokchok.auth.jwt.JwtProperties;
import com.chokchok.auth.jwt.JwtProvider;
import com.chokchok.auth.security.details.PrincipalDetails;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.stream.Collectors;

/**
 * JWT 토큰 인증을 위해 UsernamePasswordAuthenticationFilter를 커스텀한 필터
 */
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtProperties jwtProperties;
    private final JwtProvider jwtProvider;
    private final ObjectMapper objectMapper;
    private final RedisTemplate<String, Object> redisTemplate;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtProperties jwtProperties, JwtProvider jwtProvider, ObjectMapper objectMapper, RedisTemplate<String, Object> redisTemplate) {
        super(authenticationManager);
        this.authenticationManager = authenticationManager;
        this.jwtProperties = jwtProperties;
        this.jwtProvider = jwtProvider;
        this.objectMapper = objectMapper;
        this.redisTemplate = redisTemplate;

        setFilterProcessesUrl(jwtProperties.getLoginUrl());
        setAuthenticationFailureHandler((request, response, authenticationException) -> {
            new JwtFailureHandler().onAuthenticationFailure(request, response, authenticationException);
        });
    }

    /**
     * 프론트 서버에서 로그인을 시도하면 실행한다.
     * 사용자가 입력한 id, password를 기반으로 usernamePasswordToken을 발급하고 authenticationManager에게 위임한다
     *
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @return 인증된 Authentication 객체
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        LoginRequestDto loginRequestDto;
        try {
            loginRequestDto = objectMapper.readValue(request.getInputStream(), LoginRequestDto.class);
            log.info("Auth Server === Attempt Authentication");
            log.info("loginId={}", loginRequestDto.id());
        } catch (IOException e) {
            throw new InvalidException(ErrorCode.INVALID_LOGIN_REQUEST, "잘못된 로그인 요청입니다.");
        }

        // usernamePasswordAuthenticationToken 객체를 생성
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(loginRequestDto.id(),loginRequestDto.password());
        // 생성됨 token을 authenticationManager에게 전달
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    /**
     * 인증 성공 시 동작하는 후처리 메소드
     *
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param chain FilterChain
     * @param authentication Authentication
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        log.info("Auth Server === Successful Authentication");

        // 토큰 생성
        String accessToken = getAccessToken(authentication);
        String refreshToken = getRefreshToken(authentication);

        // Redis에 토큰 저장
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        String memberId = String.valueOf(principalDetails.getId());

        redisTemplate.opsForHash().put(memberId, RedisHashKey.ACCESS_TOKEN.getValue(), accessToken);
        redisTemplate.opsForHash().put(memberId, RedisHashKey.REFRESH_TOKEN.getValue(), refreshToken);

        // JWT 응답
        TokenResponseDto tokenResponse = new TokenResponseDto(
                accessToken,
                jwtProperties.getTokenPrefix(),
                jwtProperties.getAccessExpirationTime(),
                refreshToken
        );

        String result = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(tokenResponse);

        PrintWriter printWriter = response.getWriter();
        printWriter.write(result);
        printWriter.close();
    }

    /**
     * 인증 실패 시 동작하는 후처리 메소드
     *
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param authenticationException AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException, ServletException {
        log.error("login failed={}", authenticationException.toString());
        getFailureHandler().onAuthenticationFailure(request, response, authenticationException);
    }

    /**
     * 인증 객체를 JwtProvider에게 전달하여 accessToken을 발급합니다.
     *
     * @param authentication
     * @return String - AccessToken
     */
    private String getAccessToken(Authentication authentication) {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        return jwtProvider.generateAccessToken(
                principalDetails.getId(),
                principalDetails.getUsername(),
                authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())
        );
    }

    /**
     * 인증 객체를 JwtProvider에게 전달하여 refreshToken을 발급합니다.
     *
     * @param authentication
     * @return String - RefreshToken
     */
    private String getRefreshToken(Authentication authentication) {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        return jwtProvider.generateRefreshToken(
                principalDetails.getId(),
                principalDetails.getUsername(),
                authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())
        );
    }

}
