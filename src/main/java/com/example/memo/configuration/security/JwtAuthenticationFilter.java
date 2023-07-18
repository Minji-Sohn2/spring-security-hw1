package com.example.memo.configuration.security;

import com.example.memo.dto.LoginRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j(topic = "AuthenticationFilter")
class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final String AUTHORIZATION_HEADER = "Authorization";

	public JwtAuthenticationFilter() {
		setFilterProcessesUrl("api/members/login");
	}

	// 로그인 시도
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		try {
			log.info("로그인 시도");
			// json 모양의 string을 객체로 만들기
			LoginRequest requestDto = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);

			return getAuthenticationManager().authenticate(
				new UsernamePasswordAuthenticationToken(
					requestDto.email(),
					requestDto.password(),
					null
				)
			);
		} catch (IOException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	// 로그인 성공
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
		// TODO : 올바른 인증 요청에 대한 결과로 jwt token 만들고, 검증한 후에 201 response로 해당 token 세팅하기

		String username = ((UserDetails) authResult.getPrincipal()).getUsername(); // 인증 객체 속 username 가져오기
		log.info("username : " + username);
		String token = JwtUtil.createToken(username); // username으로 token 만들기
		log.info("token : " + token);
		response.addHeader(AUTHORIZATION_HEADER, token); // response 객체 header에 넣어주기
		response.setStatus(201);
	}

	// 로그인 실패
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
		response.setStatus(401);
	}
}
