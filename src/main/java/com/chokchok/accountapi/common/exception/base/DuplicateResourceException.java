package com.chokchok.accountapi.common.exception.base;

/**
 * DB 리소스 중복 에러에 사용하는 예외 클래스
 */
public class DuplicateResourceException extends RuntimeException {
    public DuplicateResourceException(String message) {
        super(message);
    }
}
