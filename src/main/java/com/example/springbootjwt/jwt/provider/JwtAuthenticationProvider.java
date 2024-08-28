package com.example.springbootjwt.jwt.provider;

import com.example.springbootjwt.jwt.token.JwtAuthenticationToken;
import com.example.springbootjwt.jwt.util.JwtTokenizer;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtTokenizer jwtTokenizer;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;

        // 토큰이 accessSecret 키를 사용해서 파싱 -> 파싱 과정에서 유효시간이나 시크릿키 변조에 대한 검증을 진행함.
        Claims claims = jwtTokenizer.parseAccessToken(authenticationToken.getToken());

        // Claims에 있는 email, authorities를 추출
        String email = claims.getSubject();
        List<GrantedAuthority> authorities = getGrantedAuthorities(claims);

        return new JwtAuthenticationToken(authorities, email, null);
    }

    private List<GrantedAuthority> getGrantedAuthorities(Claims claims) {
        List<String> roles = (List<String>) claims.get("roles");
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String role : roles) {
            authorities.add(()-> role);
        }
        return authorities;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
