package com.chokchok.auth.config;

import com.chokchok.auth.client.FeignErrorDecoder;
import com.fasterxml.jackson.databind.ObjectMapper;
import feign.codec.ErrorDecoder;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * FeignClient의 설정 Bean 등록 클래스
 */
@RequiredArgsConstructor
@Configuration
public class FeignConfig {

    private final ObjectMapper objectMapper;

    @Bean
    public ErrorDecoder errorDecoder() {
        return new FeignErrorDecoder(objectMapper);
    }
}
