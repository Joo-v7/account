package com.chokchok.accountapi.common.exception.base;

/**
 * DB에서 Entity를 찾지 못했을 때 사용하는 예외 클래스
 */
public class EntityNotFoundException extends RuntimeException {
    public EntityNotFoundException(String message) {
        super(message);
    }
}
