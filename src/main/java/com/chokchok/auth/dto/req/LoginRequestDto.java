package com.chokchok.auth.dto.req;

/**
 * 로그인 요청 DTO
 * @param id
 * @param password
 */
public record LoginRequestDto(
        String id,
        String password
) { }
