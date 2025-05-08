package com.chokchok.auth.dto.res;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * JWT 토큰 발급 후 응답에 사용되는 DTO
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class TokenResponseDto {
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("expires_in")
    private Long expiresIn;

    @JsonProperty("refresh_token")
    private String refreshToken;
}
