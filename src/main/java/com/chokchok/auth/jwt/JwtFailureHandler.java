package com.chokchok.auth.jwt;

import com.chokchok.auth.common.dto.ErrorResponseDto;
import com.chokchok.auth.common.exception.code.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

/**
 * 인증 실패 시 처리하는 핸들러 클래스
 */
@Slf4j
public class JwtFailureHandler implements AuthenticationFailureHandler {

    /**
     * 인증 실패 시 호출되는 메서드.
     *
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param exception AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.info("JWT Authentication Failed Handler called");

        ErrorResponseDto errorResponseDto = ErrorResponseDto.of(
                HttpStatus.UNAUTHORIZED.value(),
                ErrorCode.JWT_AUTHENTICATION_FAILED.getCode(),
                "Login Failed"
        );

        // ErrorResponseDto의 LocalDateTime 직렬화를 위한 ObjectMapper 설정
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(errorResponseDto));
    }
}
