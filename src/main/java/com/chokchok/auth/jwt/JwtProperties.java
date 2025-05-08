package com.chokchok.auth.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * JWT 관련 설정을 관리하는 클래스
 */
@Setter
@Getter
@Component
@ConfigurationProperties(prefix="jwt")
public class JwtProperties {

    private String secret;
    private String tokenPrefix;
    private String headerString;
    private long accessExpirationTime;
    private long refreshExpirationTime;
    private String loginUrl;

}