package com.chokchok.auth.service;

import com.chokchok.auth.config.RedisHashKey;
import com.chokchok.auth.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * 토큰 재발급, 로그아웃, 블랙 리스트 처리 관련 기능을 가지는 클래스
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class AuthenticationService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final JwtProvider jwtProvider;

    /**
     * JWT 토큰 재발급 이후 처리로, Redis에서 해당 멤버의 AccessToken을 갱신한다.
     * @param memberId
     * @param accessToken - 재발급 된 accessToken
     */
    public void doReissue(String memberId, String accessToken) {
        redisTemplate.opsForHash().delete(memberId, RedisHashKey.ACCESS_TOKEN.getValue(), accessToken);
        redisTemplate.opsForHash().put(memberId, RedisHashKey.ACCESS_TOKEN.getValue(), accessToken);
    }

    /**
     * 로그아웃 처리, Redis에서 해당 유저의 정보를 삭제한다.
     * @param memberId
     */
    public void doLogout(String memberId, String accessToken) {
        // 유저 정보 삭제
        redisTemplate.opsForHash().delete(RedisHashKey.ACCESS_TOKEN.getValue(), memberId);
        redisTemplate.opsForHash().delete(RedisHashKey.REFRESH_TOKEN.getValue(), memberId);

        // 블랙리스트에 토큰 추가
        addToBlacklist(accessToken);
    }

    /**
     * 블랙 리스트에 토큰 저장하는 메소드
     * 로그아웃 시 accessToken을 블랙 리스트에 저장한다
     * @param accessToken
     */
    public void addToBlacklist(String accessToken) {
        String key = RedisHashKey.BLACKLIST.getValue() + ":" + accessToken;
        // JWT에서 만료 날짜 추출
        Date expiredDate = jwtProvider.extractExpiration(accessToken);
        // 현재 시간
        Date now = new Date();
        // JWT의 남은 유효 시간(초)
        long remainingTimeInSeconds = (expiredDate.getTime() - now.getTime()) / 1000;

        // redis에 저장
        if(remainingTimeInSeconds > 0) {
            redisTemplate.opsForValue().set(key, expiredDate.toString(), remainingTimeInSeconds, TimeUnit.SECONDS);
        }
    }

    /**
     * 블랙리스트 확인 메소드
     * @param accessToken
     * @return boolean - 블랙리스트에 accessToken 존재 여부
     */
    public boolean isBlacklisted(String accessToken) {
        String key = RedisHashKey.BLACKLIST.getValue() + ":" + accessToken;
        return redisTemplate.hasKey(key);
    }

}
