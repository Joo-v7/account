package com.chokchok.accountapi.common.exception.dto;

import java.time.LocalDateTime;

/**
 * 에러 응답 정보를 담는 DTO 클래스
 *
 * @param status    HTTP 상태 코드
 * @param message   에러 메시지
 * @param timestamp 에러 발생 시간
 */

public record ErrorResponseDto(
        int status,
        String message,
        LocalDateTime timestamp
) {

    public static ErrorResponseDto of(int status, String message) {
        return new ErrorResponseDto(status, message, LocalDateTime.now());
    }

}
