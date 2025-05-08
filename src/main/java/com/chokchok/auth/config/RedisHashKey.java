package com.chokchok.auth.config;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Redis에서 Hash Key로 사용되는 정보들에 대한 enum 클래스입니다.
 */
@Getter
@RequiredArgsConstructor
public enum RedisHashKey {
    ACCESS_TOKEN("ACCESS_TOKEN"),
    REFRESH_TOKEN("REFRESH_TOKEN"),
    BLACKLIST("BLACKLIST");

    private final String value;
}
