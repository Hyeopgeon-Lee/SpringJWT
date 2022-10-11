package kopo.poly.controller;

import kopo.poly.auth.AuthInfo;
import kopo.poly.auth.JwtTokenProvider;
import kopo.poly.auth.JwtTokenType;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@RequestMapping(value = "/jwt")
@RequiredArgsConstructor
@Controller
public class JwtController {

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.valid.time}")
    private long refreshTokenValidTime;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    private final JwtTokenProvider jwtTokenProvider;

    @RequestMapping(value = "loginSuccess")
    public String loginSuccess(@AuthenticationPrincipal AuthInfo authInfo,
                               HttpServletResponse response, ModelMap model) throws Exception {

        log.info(this.getClass().getName() + ".loginSuccess Start!");

        // Spring Security에 저장된 정보 가져오기
        UserInfoDTO dto = authInfo.getUserInfoDTO();

        if (dto == null) {
            dto = new UserInfoDTO();

        }

        String userId = CmmUtil.nvl(dto.getUserId());
        String userName = CmmUtil.nvl(dto.getUserName());
        String userRoles = CmmUtil.nvl(dto.getRoles());

        log.info("userId : " + userId);
        log.info("userName : " + userName);
        log.info("userRoles : " + userRoles);

        // Access Token 생성
        String accessToken = jwtTokenProvider.createToken(userId, userRoles, JwtTokenType.ACCESS_TOKEN);

        ResponseCookie cookie = ResponseCookie.from(accessTokenName, accessToken)
                .domain("localhost")
                .path("/")
//                .secure(true)
//                .sameSite("None")
                .maxAge(accessTokenValidTime) // JWT Refresh Token 만료시간 설정
                .httpOnly(true)
                .build();

        // 기존 쿠기 모두 삭제하고, Cookie에 Access Token 저장하기
        response.setHeader("Set-Cookie", cookie.toString());

        cookie = null;

        // Refresh Token 생성
        // Refresh Token은 보안상 노출되면, 위험하기에 Refresh Token은 DB에 저장하고,
        // DB를 조회하기 위한 값만 Refresh Token으로 생성함
        // 본 실습은 DB에 저장하지 않고, 사용자 컴퓨터의 쿠키에 저장함
        // Refresh Token은 Access Token에 비해 만료시간을 길게 설정함
        String refreshToken = jwtTokenProvider.createToken(userId, userRoles, JwtTokenType.REFRESH_TOKEN);

        cookie = ResponseCookie.from(refreshTokenName, refreshToken)
                .domain("localhost")
                .path("/")
//                .secure(true)
//                .sameSite("None")
                .maxAge(refreshTokenValidTime) // JWT Refresh Token 만료시간 설정
                .httpOnly(true)
                .build();

        // 기존 쿠기에 Refresh Token 저장하기
        response.addHeader("Set-Cookie", cookie.toString());

//        response.setHeader

        // JSP에 값 전달하기
        model.addAttribute("userName", userName);

        log.info(this.getClass().getName() + ".loginSuccess End!");

        return "/ss/LoginSuccess";

    }


    @RequestMapping(value = "loginFail")
    public String loginFail() {

        log.info(this.getClass().getName() + ".loginFail Start!");

        log.info(this.getClass().getName() + ".loginFail End!");

        return "/ss/LoginFail";

    }


    @GetMapping(value = "logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {

        // 로그아웃 처리하기
        new SecurityContextLogoutHandler().logout(
                request, response, SecurityContextHolder.getContext().getAuthentication());

        return "/";
    }

}
