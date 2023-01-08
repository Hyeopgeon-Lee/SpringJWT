package kopo.poly.filter;

import kopo.poly.auth.JwtStatus;
import kopo.poly.auth.JwtTokenProvider;
import kopo.poly.auth.JwtTokenType;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    // JWT Token 객체
    private final JwtTokenProvider jwtTokenProvider;

    // List객체를 읽기 전용으로 설정하기
    private final List<String> url = Collections.unmodifiableList(
            Arrays.asList(
                    "/ss/login",
                    "/ss/userRegForm"
            )
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        log.info(this.getClass().getName() + ".doFilterInternal Start!");

        // 쿠키에서 Access Token 가져오기
        String accessToken = CmmUtil.nvl(jwtTokenProvider.resolveToken(request, JwtTokenType.ACCESS_TOKEN));

        log.info("accessToken : " + accessToken);

        // Access Token 유효기간 검증하기
        JwtStatus accessTokenStatus = jwtTokenProvider.validateToken(accessToken);

        log.info("accessTokenStatus : " + accessTokenStatus);

        // 유효기간 검증하기
        if (accessTokenStatus == JwtStatus.ACCESS) {

            // 토큰이 유효하면 토큰으로부터 유저 정보를 받아옵니다.
            // 받은 유저 정보 : hglee67 아이디의 권한을 SpringSecurity에 저장함
            Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);

            // SecurityContext 에 Authentication 객체를 저장합니다.
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } else if (accessTokenStatus == JwtStatus.EXPIRED ||
                accessTokenStatus == JwtStatus.DENIED) { // 만료 및 쿠키에서 삭제된 Access Token인 경우

            // Access Token이 만료되면, Refresh Token 유효한지 체크한
            // Refresh Token 확인하기
            String refreshToken = CmmUtil.nvl(jwtTokenProvider.resolveToken(request, JwtTokenType.REFRESH_TOKEN));

            // Refresh Token 유효기간 검증하기
            JwtStatus refreshTokenStatus = jwtTokenProvider.validateToken(refreshToken);

            log.info("refreshTokenStatus : " + refreshTokenStatus);

            // Refresh Token이 유효하면, Access Token 재발급
            if (refreshTokenStatus == JwtStatus.ACCESS) {
                String userId = CmmUtil.nvl(jwtTokenProvider.getUserId(refreshToken)); // 회원 아이디
                String userRoles = CmmUtil.nvl(jwtTokenProvider.getUserRoles(refreshToken)); // 회원 권한

                log.info("refreshToken userId : " + userId);
                log.info("refreshToken userRoles : " + userRoles);

                // Access Token 재 발급
                String reAccessToken = jwtTokenProvider.createToken(userId, userRoles, JwtTokenType.ACCESS_TOKEN);

                log.info("accessTokenName : " + accessTokenName);
                ResponseCookie cookie = ResponseCookie.from(accessTokenName, "")
                        .maxAge(0)
                        .build();

                // 만약, 기존 존재하는 Access Token있다면, 삭제
                response.setHeader("Set-Cookie", cookie.toString());

                cookie = null;

                cookie = ResponseCookie.from(accessTokenName, reAccessToken)
                        .domain("localhost")
                        .path("/")
//                .secure(true)
//                .sameSite("None")
                        .maxAge(accessTokenValidTime) // JWT Refresh Token 만료시간 설정
                        .httpOnly(true)
                        .build();

                response.setHeader("Set-Cookie", cookie.toString());

                // 토큰이 유효하면 토큰으로부터 유저 정보를 받아옵니다.
                // 받은 유저 정보 : hglee67 아이디의 권한을 SpringSecurity에 저장함
                Authentication authentication = jwtTokenProvider.getAuthentication(reAccessToken);

                // SecurityContext 에 Authentication 객체를 저장합니다.
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } else if (refreshTokenStatus == JwtStatus.EXPIRED) {
                log.info("Refresh Token 만료");

            } else {
                log.info("Refresh Token 오류");

            }

        }

        log.info(this.getClass().getName() + ".doFilterInternal End!");

        filterChain.doFilter(request, response);

    }

    /**
     * JwtAuthenticationFilter가 체크하지 않을 URL 체크하여 호출안하기
     * <p>
     * 기본 HTML, JS, CSS 제외
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        log.info(this.getClass().getName() + ".shouldNotFilter Start!");

        String path = CmmUtil.nvl(request.getServletPath()); // Request URI
        log.info("path : " + path);

        boolean res = false;

        // html, css, js 폴더 호출은 JWT 체크 안함
        if (path.contains("/html/") || path.contains("/css/") || path.contains("/js/")) {
            res = true;

        } else {

            // JWT 체크 하지 않는 URL 확인
            if (url.stream().anyMatch(url -> url.equalsIgnoreCase(path))) {
                res = true;
            }
        }
        return res;
    }
}
