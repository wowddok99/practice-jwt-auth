package com.example.springbootjwt.config.dummyData;

import com.example.springbootjwt.controller.MemberController;
import com.example.springbootjwt.domain.Member;
import com.example.springbootjwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
@Configuration
public class DummyDevInit{
    private final PasswordEncoder passwordEncoder;
    private final MemberService memberService;

    @Bean
    CommandLineRunner init(){
        return (args) -> {
            Member member = new Member();
            member.setEmail("wowddok99@gmail.com");
            member.setName("전상은");
            member.setPassword(passwordEncoder.encode("okok35371s##"));

            Member saveMember = memberService.addMember(member);
        };
    }
}
