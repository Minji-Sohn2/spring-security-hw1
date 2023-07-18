package com.example.memo.aop;

import com.example.memo.domain.model.AuthorizedMember;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class AuthorizedMemberAop {

    @Pointcut("execution(* com.example.memo.controller.api.MemberController.getMemberInfo())")
    private void getMemberInfo() {}

    @Around("getMemberInfo()")
    public Object deduplication(ProceedingJoinPoint joinPoint) throws Throwable {

        AuthorizedMember authorizedMember = (AuthorizedMember) joinPoint.getArgs()[0];

        return joinPoint.proceed();
    }
}
