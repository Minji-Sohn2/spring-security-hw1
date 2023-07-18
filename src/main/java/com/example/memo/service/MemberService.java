package com.example.memo.service;

import com.example.memo.configuration.security.JwtUtil;
import com.example.memo.domain.entity.Member;
import com.example.memo.domain.model.AuthorizedMember;
import com.example.memo.dto.LoginRequest;
import com.example.memo.dto.SignupRequest;
import com.example.memo.repository.MemberRepository;
import java.time.LocalDateTime;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService implements UserDetailsService {

	private final MemberRepository memberRepository;
	private final PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		Member member = memberRepository.findByEmail(email);
		if (member == null) {
			throw new UsernameNotFoundException(email);
		}
		return new AuthorizedMember(member);
	}

	public void signup(SignupRequest signupRequest) {
		Member member = new Member(signupRequest.email(), signupRequest.name(),
			passwordEncoder.encode(signupRequest.password()), Set.of("ROLE_MEMBER"),
			LocalDateTime.now());

		memberRepository.save(member);
	}

	public String login(LoginRequest loginRequest) {
		// 받아온 email로 회원 확인
		Member member = memberRepository.findByEmail(loginRequest.email());
		// 해당 email로 등록된 회원이 없다면
		if (member == null) {
			throw new UsernameNotFoundException(loginRequest.email());
		}
		// 비밀번호가 일치하지 않다면
		if (!passwordEncoder.matches(loginRequest.password(), member.getPassword())) {
			throw new BadCredentialsException("잘못된 요청입니다. 아이디 또는 비밀번호를 확인해주세요.");
		}

		return JwtUtil.createToken(loginRequest.email());
	}
}
