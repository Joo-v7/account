package com.chokchok.auth.common.exception.base;

import com.chokchok.auth.common.exception.code.ErrorCode;
import lombok.Getter;

/**
 * feign 관련 예외 처리 클래스
 */
@Getter
public class FeignClientException extends RuntimeException {
    private final ErrorCode errorCode;

    public FeignClientException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode=errorCode;
    }
}
