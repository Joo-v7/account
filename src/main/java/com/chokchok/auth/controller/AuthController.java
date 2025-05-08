package com.chokchok.auth.controller;

import com.chokchok.auth.common.dto.ResponseDto;
import com.chokchok.auth.common.exception.base.InvalidException;
import com.chokchok.auth.common.exception.code.ErrorCode;
import com.chokchok.auth.config.RedisHashKey;
import com.chokchok.auth.dto.res.TokenResponseDto;
import com.chokchok.auth.jwt.JwtProperties;
import com.chokchok.auth.jwt.JwtProvider;
import com.chokchok.auth.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * 재발급, 로그아웃, 블랙리스트 여부 확인을 위한 컨트롤러 클래스입니다.
 */
@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final JwtProperties jwtProperties;
    private final JwtProvider jwtProvider;
    private final RedisTemplate<String, Object> redisTemplate;

    private static final String X_MEMBER_ID = "X-MEMBER-ID";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * AccessToken 재발급
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @return ResponseDto
     * @throws IOException
     */
    @PostMapping("/reissue")
    public ResponseDto<TokenResponseDto> reissue(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String accessToken = request.getHeader(jwtProperties.getHeaderString());
        String memberId = request.getHeader(X_MEMBER_ID);

        log.info("Auth Server === Token Reissue Called");

        // 헤더의 AccessToken 검증
        if(isValidHeader(accessToken)) {
            throw new InvalidException(ErrorCode.INVALID_ACCESS_TOKEN_REQUEST, "Authorization 헤더가 없거나, 유효하지 않은 토큰입니다.");
        }

        // redis 식별키(memberId) 검증
        if(!isValidKey(memberId)) {
            throw new InvalidException(ErrorCode.INVALID_MEMBER_SESSION, "이미 로그아웃 된 사용자입니다.");
        }

        // refresh token 유효성 검증
        if(!isValidRefreshToken(memberId)) {
            throw new InvalidException(ErrorCode.INVALID_REFRESH_TOKEN_REQUEST, "refreshToken이 만료되었습니다.");
        }

        // refresh token 기반으로 accessToken 재발급
        String refreshToken = Objects.requireNonNull(redisTemplate.opsForHash().get(memberId, RedisHashKey.REFRESH_TOKEN.getValue())).toString();
        String username = jwtProvider.extractUsername(refreshToken);
        List<String> roles = jwtProvider.extractRoles(refreshToken);
        String reissuedAccessToken = jwtProvider.tokenReissue(Long.valueOf(memberId), username, roles);

        // redis에 갱신
        authenticationService.doReissue(memberId, reissuedAccessToken);

        // JWT 토큰 응답 생성
        TokenResponseDto tokenResponseDto = new TokenResponseDto(
                reissuedAccessToken,
                jwtProperties.getTokenPrefix(),
                jwtProperties.getAccessExpirationTime(),
                refreshToken
        );

        return ResponseDto.<TokenResponseDto>builder()
                .success(true)
                .status(HttpStatus.OK)
                .data(tokenResponseDto)
                .build();
    }

    @PostMapping("/logout")
    public ResponseDto<Void> logout(@RequestHeader(X_MEMBER_ID) String memberId, @RequestHeader(AUTHORIZATION_HEADER) String accessToken) {
        log.info("Auth Server === Token Logout Called");

        // 헤더의 AccessToken 검증
        if(isValidHeader(accessToken)) {
            throw new InvalidException(ErrorCode.INVALID_ACCESS_TOKEN_REQUEST, "Authorization 헤더가 없거나, 유효하지 않은 토큰입니다.");
        }

        // redis 식별키(memberId) 검증
        if(!isValidKey(memberId)) {
            throw new InvalidException(ErrorCode.INVALID_MEMBER_SESSION, "이미 로그아웃 된 사용자입니다.");
        }

        // logout - redis에 있는 정보 삭제, accessToken 블랙리스트 등록
        authenticationService.doLogout(memberId, accessToken);

        return ResponseDto.<Void>builder()
                .success(true)
                .status(HttpStatus.OK)
                .build();
    }

    /**
     * Gateway의 JWT Filter에서 accessToken의 블랙리스트 존재 여부를 확인합니다.
     * @param accessToken
     * @return boolean - 토큰의 블랙리스트 존재 여부
     */
    @GetMapping("/blacklist/{accessToken}")
    public boolean isTokenBlacklisted(@PathVariable String accessToken) {
        return authenticationService.isBlacklisted(accessToken);
    }

    /**
     * Request Header에 Authorization가 있고, AccessToken이 유효한지 검증하는 메소드
     *
     * @param accessToken
     * @return boolean
     */
    private boolean isValidHeader(String accessToken) {
        return Objects.isNull(accessToken) ||
                !accessToken.startsWith(jwtProperties.getTokenPrefix()) ||
                !jwtProvider.isValidToken(accessToken.substring(7));
    }

    /**
     * RefreshToken이 유효한지 검증하는 메소드
     *
     * @param memberId
     * @return
     */
    private boolean isValidRefreshToken(String memberId) {
        String refreshToken = Objects.requireNonNull(redisTemplate.opsForHash().get(memberId, RedisHashKey.REFRESH_TOKEN.getValue())).toString();

        long exp = jwtProvider.extractExpiration(refreshToken).getTime();

        long now = new Date().getTime();

        return exp > now;
    }

    /**
     * 식별키가 Redis에 유효한지 검증하는 메소드
     *
     * @param memberId
     * @return boolean
     */
    private boolean isValidKey(String memberId) {
        return !redisTemplate.opsForHash().keys(memberId).isEmpty();
    }

    @GetMapping("/test")
    public ResponseDto<?> test() {
        return ResponseDto.<Void>builder()
                .success(true)
                .status(HttpStatus.OK)
                .build();
    }

}