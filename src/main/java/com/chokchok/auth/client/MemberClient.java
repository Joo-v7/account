package com.chokchok.auth.client;

import com.chokchok.auth.dto.res.MemberLoginInfoResponseDto;
import com.chokchok.auth.common.dto.ResponseDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * chokchok-api의 회원 관련하여 통신하는 Feign Client
 */
@FeignClient(name = "CHOKCHOK-API")
public interface MemberClient {

    /**
     * 이메일을 통해 회원 정보를 조회하는 메서드
     * 로그인 시 사용됩니다.
     * @param email
     * @return 회원 정보 응답 (MemberLoginResponseDto)
     */
    @GetMapping("/api/members/login/{email}")
    ResponseDto<MemberLoginInfoResponseDto> getMemberInfoByEmail(@PathVariable String email);
}
