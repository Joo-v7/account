package com.chokchok.auth.security.details;

import com.chokchok.auth.dto.res.MemberLoginInfoResponseDto;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Spring Security의 인증 처리를 위한 UserDetails 구현체
 */
public class PrincipalDetails implements UserDetails {

    private final MemberLoginInfoResponseDto memberLoginInfoResponseDto;

    public PrincipalDetails(MemberLoginInfoResponseDto memberLoginInfoResponseDto) {
        this.memberLoginInfoResponseDto = memberLoginInfoResponseDto;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> roles = new ArrayList<>();

        roles.add(new SimpleGrantedAuthority(memberLoginInfoResponseDto.memberRole()));

        return roles;
    }

    public Long getId() {
        return memberLoginInfoResponseDto.id();
    }

    @Override
    public String getPassword() {
        return memberLoginInfoResponseDto.password();
    }

    @Override
    public String getUsername() {
        return memberLoginInfoResponseDto.email();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
