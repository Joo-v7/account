package com.chokchok.auth.jwt;

import com.chokchok.auth.common.exception.base.InvalidException;
import com.chokchok.auth.common.exception.code.ErrorCode;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

/**
 * JWT(Json Web Token)를 생성하고 파싱하는 클래스입니다.
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class JwtProvider {

    private final JwtProperties jwtProperties;

    /**
     * JWT를 생성하기 위해 HMAC-SHA256 알고리즘으로 JWT에 서명할 키를 생성
     *
     * @return SecretKey - 대칭키 방식이므로 secretkey 반환
     */
    private SecretKey getSecretKey() {
        String secretKey = jwtProperties.getSecret();
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);

        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * JWT 토큰 발급하는 메소드
     *
     * @param id - 멤버의 ID(P.K.)
     * @param username - 회원의 email
     * @param roles - 회원의 권한
     * @param tokenExpireTime - 토큰의 유효 시간
     * @return String - 발급한 JWT 토큰
     */
    private String generateToken(Long id, String username, List<String> roles, long tokenExpireTime) {
        Date now = new Date();

        return Jwts.builder()
                .header()
                    .add("typ", "JWT")
                    .and()
                .claims()
                    .add("id", id)
                    .add("email", username)
                    .add("roles", roles)
                    .and()
                .subject(username)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + tokenExpireTime))
                .signWith(getSecretKey())
                .compact();
    }

    /**
     * AccessToken을 발급하는 메소드
     *
     * @param id - 멤버의 ID(P.K.)
     * @param username - 회원의 email
     * @param roles - 회원의 권한
     * @return String - JWT 토큰으로 발급한 AccessToken
     */
    public String generateAccessToken(Long id, String username, List<String> roles) {
        return generateToken(id, username, roles, jwtProperties.getAccessExpirationTime());
    }

    /**
     * RefreshToken 발급하는 메소드
     *
     * @param id - 멤버의 ID(P.K.)
     * @param username - 회원의 email
     * @param roles - 회원의 권한
     * @return String - JWT 토큰으로 발급한 RefreshToken
     */
    public String generateRefreshToken(Long id, String username, List<String> roles) {
        return generateToken(id, username, roles, jwtProperties.getRefreshExpirationTime());
    }

    /**
     * JWT 토큰을 파싱하여 payload에 들어있는 회원의 id을 반환하는 메소드
     *
     * @param token
     * @return String - 회원 id
     */
    public String extractId(String token) {
        try {

            Object id = Jwts.parser()
                    .verifyWith(getSecretKey()).build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .get("id");

            return String.valueOf(id);

        } catch(JwtException e) {
            throw new InvalidException(ErrorCode.INVALID_REQUEST_TOKEN, "유효하지 않은 JWT 토큰");
        }
    }

    /**
     * JWT 토큰을 파싱하여 payload에 들어있는 회원의 username(email)을 반환하는 메소드
     *
     * @param token
     * @return String - 회원 username(email)
     */
    public String extractUsername(String token) {
        try {

            Object username = Jwts.parser()
                    .verifyWith(getSecretKey()).build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();

            return String.valueOf(username);

        } catch(JwtException e) {
            throw new InvalidException(ErrorCode.INVALID_REQUEST_TOKEN, "유효하지 않은 JWT 토큰");
        }
    }

    /**
     * JWT 토큰을 파싱하여 payload에 들어있는 회원의 roles를 반환하는 메소드
     * @param token - JWT
     * @return List<String> - roles
     */
    public List<String> extractRoles(String token) {
        try {

           Object roles = Jwts.parser()
                    .verifyWith(getSecretKey()).build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .get("roles");

           return List.of(roles.toString());

        } catch(JwtException e) {
            throw new InvalidException(ErrorCode.INVALID_REQUEST_TOKEN, "유효하지 않은 JWT 토큰");
        }
    }

    /**
     * JWT 토큰의 만료 날짜을 추출하는 메소드
     *
     * @param token - JWT
     * @return Date - 토큰의 만료 날짜
     */
    public Date extractExpiration(String token) {
        try {

            return Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration();

        } catch(JwtException e) {
            throw new InvalidException(ErrorCode.INVALID_REQUEST_TOKEN, "유효하지 않은 JWT 토큰");
        }
    }

    /**
     * JWT 토큰을 재발급하는 메소드
     *
     * @param id - member의 P.K.
     * @param username - 로그인에 사용된 ID로 email 입니다.
     * @param roles - member의 role
     * @return String - 재발급한 accessToken
     */
    public String tokenReissue(Long id, String username, List<String> roles) {
        return generateAccessToken(id, username, roles);
    }

    /**
     * secretKey를 기반으로 JWT 토큰의 유효성 검사하는 메소드
     *
     * @param token
     * @return boolean - 토큰의 유효성 판별 결과
     */
    public boolean isValidToken(String token) {
        try {

            Jwts.parser().verifyWith(getSecretKey()).build();
            return true;

        } catch(JwtException e) {
            return false;
        }
    }

}
