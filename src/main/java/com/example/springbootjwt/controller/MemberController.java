package com.example.springbootjwt.controller;

import com.example.springbootjwt.domain.Member;
import com.example.springbootjwt.domain.RefreshToken;
import com.example.springbootjwt.domain.Role;
import com.example.springbootjwt.dto.MemberLoginDto;
import com.example.springbootjwt.dto.MemberLoginResponseDto;
import com.example.springbootjwt.dto.MemberSignupDto;
import com.example.springbootjwt.dto.MemberSignupResponseDto;
import com.example.springbootjwt.dto.RefreshTokenDto;
import com.example.springbootjwt.jwt.util.JwtTokenizer;
import com.example.springbootjwt.service.MemberService;
import com.example.springbootjwt.service.RefreshTokenService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties.Lettuce.Cluster.Refresh;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {
    private final JwtTokenizer jwtTokenizer;
    private final MemberService memberService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/signup")
    public ResponseEntity signup(@RequestBody @Valid MemberSignupDto memberSignupDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        Member member = new Member();
        member.setEmail(memberSignupDto.getEmail());
        member.setName(memberSignupDto.getName());
        // 요청받은 패스워드는 인코딩 처리 -> BCryptPasswordEncoder
        member.setPassword(passwordEncoder.encode(memberSignupDto.getPassword()));

        Member saveMember = memberService.addMember(member);

        MemberSignupResponseDto memberSignupResponseDto = new MemberSignupResponseDto();
        memberSignupResponseDto.setMemberId(saveMember.getMemberId());
        memberSignupResponseDto.setEmail(saveMember.getEmail());
        memberSignupResponseDto.setName(saveMember.getName());
        memberSignupResponseDto.setRegdate(saveMember.getRegdate());

        return new ResponseEntity<>(memberSignupResponseDto, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity signup(@RequestBody @Valid MemberLoginDto memberLoginDto, HttpServletResponse response, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        // email이 없을 경우 Exception 발생.
        Member member = memberService.findByEmail(memberLoginDto.getEmail());
        if(!passwordEncoder.matches(memberLoginDto.getPassword(), member.getPassword())){
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        // List<Role> ===> List<String>
        List<String> roles = member.getRoles().stream().map(Role::getName).collect(Collectors.toList());
        System.out.println("test1 => " + roles);

        // JWT 토큰 생성
        String accessToken = jwtTokenizer.createAccessToken(member.getMemberId(), member.getEmail(), roles);
        String refreshToken = jwtTokenizer.createRefreshToken(member.getMemberId(), member.getEmail(), roles);

        // Refresh Token을 DB에 저장 -> 추후 Redis 적용 예정
        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setValue(refreshToken);
        refreshTokenEntity.setMemberId(member.getMemberId());
        refreshTokenService.addRefreshToken(refreshTokenEntity);

        // HttpOnly 쿠키에 RefreshToken을 담아서 리턴
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        MemberLoginResponseDto loginResponse = MemberLoginResponseDto.builder()
                .accessToken(accessToken)
                .memberId(member.getMemberId())
                .nickname(member.getName())
                .build();
        return new ResponseEntity<>(loginResponse, HttpStatus.OK);
    }

    @DeleteMapping("/logout")
    public ResponseEntity logout(@RequestBody RefreshTokenDto refreshTokenDto) {
        refreshTokenService.deleteRefreshToken(refreshTokenDto.getRefreshToken());
        return new ResponseEntity("로그아웃 완료", HttpStatus.OK);
    }

    @PostMapping("/refreshToken")
    public ResponseEntity requestRefresh(@RequestBody RefreshTokenDto refreshTokenDto, HttpServletResponse response) {
        // 기존 리프레시 토큰이 있는지 체크
        RefreshToken refreshToken = refreshTokenService.findRefreshToken(refreshTokenDto.getRefreshToken());

        // 기존 리프레시 토큰에서 Claims 추출
        Claims claims = jwtTokenizer.parseRefreshToken(refreshToken.getValue());

        // 기존 리프레시 토큰에서 userId, roles, email 추출
        Long userId = Long.valueOf((Integer)claims.get("userId"));
        List roles = (List) claims.get("roles");
        String email = claims.getSubject();

        // userId가 멤버 테이블에 존재하는지 체크
        Member member = memberService.getMember(userId);

        // AcessToken, RefreshToken 생성
        String newAccessToken = jwtTokenizer.createAccessToken(userId, email, roles);
        String newRefreshToken = jwtTokenizer.createRefreshToken(userId, email, roles);

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setId(refreshToken.getId());
        refreshTokenEntity.setValue(newRefreshToken);
        refreshTokenEntity.setMemberId(member.getMemberId());

        // 기존 리프레시 토큰 수정
        refreshTokenService.updateRefreshToken(refreshTokenEntity);

        // HttpOnly 쿠키에 RefreshToken을 담아서 리턴
        Cookie cookie = new Cookie("refreshToken", newRefreshToken);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        MemberLoginResponseDto loginResponse = MemberLoginResponseDto.builder()
                .accessToken(newAccessToken)
                .memberId(member.getMemberId())
                .nickname(member.getName())
                .build();

        return new ResponseEntity(loginResponse, HttpStatus.OK);
    }

}
