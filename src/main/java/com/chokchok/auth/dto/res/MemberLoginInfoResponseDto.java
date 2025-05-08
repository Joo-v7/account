package com.chokchok.auth.dto.res;

/**
 * chokchok API 서버에서 로그인에 필요한 회원 정보를 요청 시 결과를 받아오기 위한 DTO
 */
public record MemberLoginInfoResponseDto(
        Long id,
        String username,
        String email,
        String password, // BCrypt로 암호화 되어 있음
        String status,
        String memberRole
) {}
