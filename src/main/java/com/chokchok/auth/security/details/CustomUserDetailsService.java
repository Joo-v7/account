package com.chokchok.auth.security.details;

import com.chokchok.auth.client.MemberClient;
import com.chokchok.auth.common.dto.ResponseDto;
import com.chokchok.auth.dto.res.MemberLoginInfoResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Spring Security에서 사용자 인증을 위한 사용자 정보를 제공하는 UserDetailsService를 구현한 CustomUserDetailsService
 */
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberClient memberClient;

    /**
     * 주어진 username(email로 사용함)을 기준으로 회원 정보를 조회하여 UserDetails 구현체인 PrincipalDetails 객체를 반환
     *
     * @param username
     * @return UserDetails를 구현한 PrincipalDetails
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        ResponseDto<MemberLoginInfoResponseDto> response = memberClient.getMemberInfoByEmail(username);
        MemberLoginInfoResponseDto memberLoginInfoResponseDto = response.getData();

        return new PrincipalDetails(memberLoginInfoResponseDto);
    }

}
