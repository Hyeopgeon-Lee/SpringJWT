package kopo.poly.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 로그인된 URL 처리할 컨트롤러
 * Spring Security로 로그인 및 권한 체크를 쉽게 하기 위해 분리함
 */
@Slf4j
@RequestMapping(value = "/user")
@RequiredArgsConstructor
@Controller
public class UserController {

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    @GetMapping(value = "logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {

        // Access Token 삭제하기
        ResponseCookie cookie = ResponseCookie.from(accessTokenName, "")
                .domain("localhost")
                .path("/")
                .maxAge(0) // JWT Refresh Token 만료시간 설정
                .build();

        response.setHeader("Set-Cookie", cookie.toString());

        // Refresh Token 삭제하기
        cookie = ResponseCookie.from(refreshTokenName, "")
                .domain("localhost")
                .path("/")
                .maxAge(0) // JWT Refresh Token 만료시간 설정
                .build();

        response.setHeader("Set-Cookie", cookie.toString());

        // Spring SecurityContext 저장된 로그인된 사용자의 권한 정보 삭제하기
        new SecurityContextLogoutHandler().logout(
                request, response, SecurityContextHolder.getContext().getAuthentication());

        return "ss/logout";
    }
}
