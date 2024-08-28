package com.example.springbootjwt.service;

import com.example.springbootjwt.domain.Member;
import com.example.springbootjwt.domain.Role;
import com.example.springbootjwt.repository.MemberRepository;
import com.example.springbootjwt.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final RoleRepository roleRepository;
    @Transactional(readOnly = true)
    public Member findByEmail(String email){
        return memberRepository.findByEmail(email).orElseThrow(() -> new IllegalArgumentException("해당 email이 존재하지 않습니다."));
    }
    @Transactional
    public Member addMember(Member member) {
        Optional<Role> userRole = roleRepository.findByName("ROLE_USER");
        member.addRole(userRole.get());
        Member saveMember = memberRepository.save(member);
        return saveMember;
    }

    @Transactional(readOnly = true)
    public Member getMember(Long memberId){
        return memberRepository.findById(memberId).orElseThrow(() -> new IllegalArgumentException("해당 memberId가 존재하지 않습니다."));
    }
}

