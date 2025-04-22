package com.chokchok.accountapi.common.exception.base;

/**
 * Enum 값이 올바르지 않을 때 사용하는 예외 클래스
 */
public class InvalidEnumValueException extends RuntimeException {
    public InvalidEnumValueException(String message) {
        super(message);
    }
}
