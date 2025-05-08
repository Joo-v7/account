package com.chokchok.auth.jwt;

import com.chokchok.auth.common.dto.ResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
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

        ResponseDto<String> responseDto = ResponseDto.<String>builder()
                .success(false)
                .status(HttpStatus.UNAUTHORIZED)
                .data("authentication failed")
                .build();

        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        response.setContentType("application/json");
        response.getWriter().write(new ObjectMapper().writeValueAsString(responseDto));
    }
}
