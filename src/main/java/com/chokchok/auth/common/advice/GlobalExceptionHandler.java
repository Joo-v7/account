package com.chokchok.auth.common.advice;

import com.chokchok.auth.common.dto.ErrorResponseDto;
import com.chokchok.auth.common.exception.base.FeignClientException;
import com.chokchok.auth.common.exception.base.InvalidException;
import com.chokchok.auth.common.exception.code.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 전역 예외 처리를 위한 Controller Advice
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 유효하지 않은 요청에 대한 예외 처리
     * @param e - InvalidException
     * @return ErrorResponseDto
     */
    @ExceptionHandler(InvalidException.class)
    public ResponseEntity<?> handleInvalidException(InvalidException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponseDto.of(HttpStatus.BAD_REQUEST.value(), e.getErrorCode().getCode(), e.getMessage()));
    }

    /**
     * Feign 관련 에러 처리
     * @param e - FeignClientException
     * @return ErrorResponseDto
     */
    @ExceptionHandler(FeignClientException.class)
    public ResponseEntity<?> handleFeignClientException(FeignClientException e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponseDto.of(HttpStatus.INTERNAL_SERVER_ERROR.value(), e.getErrorCode().getCode(), e.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponseDto.of(HttpStatus.INTERNAL_SERVER_ERROR.value(), ErrorCode.AUTH_API_SERVER_ERROR.getCode(), e.getMessage()));
    }

}
