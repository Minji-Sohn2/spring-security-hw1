package com.example.memo.configuration.security;

import com.example.memo.domain.entity.Member;
import com.example.memo.service.MemberService;
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
				log.error("유효하지 않은 토큰");
				return;
			}

			// token의 claim 부분에서 "auth"의 value값 가져오기
			Claims userInfo = JwtUtil.getUserInfoFromToken(token);
//			String username = userInfo.getSubject();
//			Member member = null;

			// 만약 "ROLE_MEMBER" 권한이 없다면
			if(!userInfo.get("auth").equals("ROLE_MEMBER")) {
				log.error("권한 없음");
				return;
			} else {
				// SecurityContextHolder에 setContext
				SecurityContext context = SecurityContextHolder.createEmptyContext();

				//member -> userDetails, 인증객체 생성
				UserDetails userDetails; //= MemberService.loadUserByUsername;
				Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				context.setAuthentication(authentication);

				SecurityContextHolder.setContext(context);
			}
		}
		filterChain.doFilter(request, response);
	}
}
