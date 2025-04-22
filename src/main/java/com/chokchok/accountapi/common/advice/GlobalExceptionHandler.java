package com.chokchok.accountapi.common.advice;

import com.chokchok.accountapi.common.exception.base.DuplicateResourceException;
import com.chokchok.accountapi.common.exception.base.EntityNotFoundException;
import com.chokchok.accountapi.common.exception.base.InvalidEnumValueException;
import com.chokchok.accountapi.common.exception.dto.ErrorResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 전역 예외를 처리하는 핸들러 클래스
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 엔티티 찾지 못할 때 예외 처리
     * @return ErrorResponseDto
     */
    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<?> handleEntityNotFoundException(EntityNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ErrorResponseDto.of(HttpStatus.NOT_FOUND.value(), e.getMessage()));
    }

    /**
     * DB 리소스 중복 예외 처리
     * @return ErrorResponseDto
     */
    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<?> handleDuplicateResourceException(DuplicateResourceException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponseDto.of(HttpStatus.BAD_REQUEST.value(), e.getMessage()));
    }

    /**
     * 유효성 검사 실패 예외 처리
     * @return ErrorResponseDto
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponseDto.of(HttpStatus.BAD_REQUEST.value(), e.getMessage()));
    }

    /**
     * 올바르지 않은 Enum 예외 처리
     * @return ErrorResponseDto
     */
    @ExceptionHandler(InvalidEnumValueException.class)
    public ResponseEntity<?> handleInvalidEnumValueException(InvalidEnumValueException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponseDto.of(HttpStatus.BAD_REQUEST.value(), e.getMessage()));
    }

}
