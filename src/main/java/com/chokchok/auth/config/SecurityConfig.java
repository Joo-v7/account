package com.chokchok.auth.config;

import com.chokchok.auth.client.MemberClient;
import com.chokchok.auth.jwt.JwtFailureHandler;
import com.chokchok.auth.jwt.JwtProperties;
import com.chokchok.auth.jwt.JwtProvider;
import com.chokchok.auth.security.details.CustomUserDetailsService;
import com.chokchok.auth.security.filter.JwtAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security의 설정 Bean 등록 클래스
 */
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final MemberClient memberClient;
    private final JwtProvider jwtProvider;
    private final JwtProperties jwtProperties;
    private final ObjectMapper objectMapper;
    private final RedisTemplate<String, Object> redisTemplate;

    @Bean
//    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.logout(AbstractHttpConfigurer::disable);
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.addFilterAt(new JwtAuthenticationFilter(
                authenticationManager(null),
                jwtProperties,
                jwtProvider,
                objectMapper,
                redisTemplate
        ), UsernamePasswordAuthenticationFilter.class);
//        http.addFilter(jwtAuthenticationFilter());
//        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        http.authorizeHttpRequests(authorize -> authorize
                .anyRequest().permitAll()
        );

        return http.build();
    }

    /**
     * JWT 인증을 위해 UsernamePasswordAuthenticationFilter를 커스텀한 필터의 설정
     * @return JwtAuthenticationFilter
     * @throws Exception
     */
//    private JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
//        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(
//                authenticationManager(null),
//                jwtProperties,
//                jwtProvider,
//                objectMapper,
//                redisTemplate
//        );
//
//        jwtAuthenticationFilter.setFilterProcessesUrl("/auth/login");
//        jwtAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
//
//        return jwtAuthenticationFilter;
//    }

//    @Bean
//    public UsernamePasswordAuthenticationFilter jwtAuthenticationFilter() throws Exception {
//        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(
//                authenticationManager(null),
//                jwtProperties,
//                jwtProvider,
//                objectMapper,
//                redisTemplate
//        );
//
//        jwtAuthenticationFilter.setFilterProcessesUrl("/auth/login");
//        jwtAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
//
//        return jwtAuthenticationFilter;
//    }

    /**
     * AuthenticationManager 빈으로 등록합니다
     * @param authenticationConfiguration 인증 구성
     * @return 인증 정보를 관리하는 AuthenticationManager
     * @throws Exception getAuthenticationManager()에서 발생하는 예외
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * DB(chokchok-api)에서 조회한 사용자 정보를 기반으로 인증을 처리하는 DaoAuthenticationProvider를 커스텀하여 Bean으로 등록합니다.
     * @return 인증 정보를 처리하는 DaoAuthenticationProvider
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(customUserDetailsService());
        return daoAuthenticationProvider;
    }

    /**
     * 사용자 인증 정보를 DB(chokchok-api)에서 조회하는 CustomUserDetailsService를 Bean으로 등록합니다.
     * DaoAuthenticationProvider에서 사용자 정보를 조회하는 역할로, DB(shop api)에서 회원을 조회하는 역할을 합니다.
     * @return 사용자 인증 정보를 처리하는 CustomUserDetailsService
     */
    @Bean
    public CustomUserDetailsService customUserDetailsService() {
        return new CustomUserDetailsService(memberClient);
    }

    /**
     * 인증 실패시 동작하는 핸들러
     * @return AuthenticationFailureHandler - JwtFailureHandler
     */
//    @Bean
//    public AuthenticationFailureHandler authenticationFailureHandler() {
//        return new JwtFailureHandler();
//    }

    /**
     * 비밀번호 암호화에 사용되는 PasswordEncoder을 Bean을 등록합니다.
     * @return 비밀번호 암호화 및 검증을 위한 PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
