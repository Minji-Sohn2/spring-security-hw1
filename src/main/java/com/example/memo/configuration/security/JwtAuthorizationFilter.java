package com.example.memo.configuration.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j(topic = "JwtAuthorizationFilter")
class JwtAuthorizationFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		// TODO : 요청에 들어온 JWT를 parsing해서 "ROLE_MEMBER" 권한이 있는지 확인하고, SecurityContextHolder에 context 설정하기

		// request header에서 token 가져오기
		String token = JwtUtil.getTokenFromHeader(request);
		log.info(token);

		if(StringUtils.hasText(token)) {
			token = token.substring(7);

			if (!JwtUtil.validateToken(token)) {
				log.error("Token Error");
				return;
			}

			// token의 claim 부분에서 "auth"의 value값 가져오기
			Claims userInfo = JwtUtil.getUserInfoFromToken(token);
			String username = userInfo.getSubject();
			User user = null;

			// 만약 "ROLE_MEMBER" 권한이 있다면
			if(!user.getAuthorities().isEmpty()) {
				// SecurityContextHolder에 setContext
				SecurityContext context = SecurityContextHolder.createEmptyContext();

				//인증객체 생성
				UserDetails userDetails = null;
				Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, user.getAuthorities());
				context.setAuthentication(authentication);

				SecurityContextHolder.setContext(context);

			}
		}
		filterChain.doFilter(request, response);
	}
}
